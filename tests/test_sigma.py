"""Sigma compilation and sweeping.

The live tests need a real Elasticsearch (NECROPSY_TEST_ELASTIC_URL) because
the failure this code is written against -- a rule that compiles fine and
matches nothing because the index maps a field as text, or lacks a multi-field
pySigma assumed -- is invisible to a test double.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from necropsy.attack import sigma
from necropsy.elastic.client import ElasticClient
from necropsy.elastic.sysmon import TelemetryWindow
from necropsy.enums import Severity

LIVE_URL = os.environ.get("NECROPSY_TEST_ELASTIC_URL")
live = pytest.mark.skipif(not LIVE_URL, reason="set NECROPSY_TEST_ELASTIC_URL to run")

pytestmark = pytest.mark.skipif(not sigma.have_sigma(), reason="pySigma not installed")

CHANNEL = "Microsoft-Windows-Sysmon/Operational"
KEYWORD = {"type": "keyword"}
ECS_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "event": {"properties": {"code": KEYWORD}},
            "host": {"properties": {"name": KEYWORD}},
            "winlog": {"properties": {"channel": KEYWORD}},
            "registry": {"properties": {"path": KEYWORD}},
            "process": {
                "properties": {
                    "executable": KEYWORD, "command_line": KEYWORD,
                    "parent": {"properties": {"executable": KEYWORD}},
                }
            },
        }
    }
}


def _window(now: datetime) -> TelemetryWindow:
    return TelemetryWindow(
        start=now - timedelta(minutes=10), end=now + timedelta(minutes=10), host="WIN-LAB-01"
    )


# -- compilation, no cluster needed -----------------------------------------


def test_packaged_rules_compile() -> None:
    rules, sources = sigma.compile_rules()
    assert all(s.error is None for s in sources), [s.error for s in sources]
    assert len(rules) >= 8


def test_rules_translate_sysmon_fields_to_ecs() -> None:
    """Without the pipeline every rule would query fields the lab does not have."""
    rules, _ = sigma.compile_rules()
    run_key = next(r for r in rules if "Run Key" in r.title)
    assert "registry.path" in run_key.query
    assert "TargetObject" not in run_key.query
    assert "event.code:13" in run_key.query


def test_rule_metadata_becomes_finding_metadata() -> None:
    rules, _ = sigma.compile_rules()
    shadow = next(r for r in rules if "Shadow Copy" in r.title)
    assert shadow.severity is Severity.CRITICAL
    assert shadow.attack_techniques == ["T1490"]
    assert 0 < shadow.confidence <= 1


def test_experimental_rules_are_trusted_less_than_stable_ones() -> None:
    from necropsy.attack.sigma import CompiledRule

    def rule(status: str) -> CompiledRule:
        return CompiledRule(id="x", title="t", description="", level="high",
                            status=status, source="s", query="q")

    assert rule("stable").confidence > rule("test").confidence > rule("experimental").confidence


def test_a_broken_rule_file_does_not_blind_the_set(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    broken = tmp_path / "rules"
    broken.mkdir()
    (broken / "bad.yml").write_text("title: nope\ndetection: {this: is not sigma}\n")
    monkeypatch.setenv("NECROPSY_SIGMA_RULE_PATHS", str(broken))
    from necropsy.config import get_settings

    get_settings.cache_clear()
    sigma._compile.cache_clear()

    rules, sources = sigma.compile_rules()
    assert any(s.error for s in sources if not s.packaged)
    assert len(rules) >= 8, "packaged rules must still load"
    sigma._compile.cache_clear()


def test_strip_caseless_rewrites_only_the_suffix() -> None:
    query = "process.executable.caseless:*\\x.exe AND process.command_line:*y*"
    assert sigma.strip_caseless(query) == "process.executable:*\\x.exe AND process.command_line:*y*"


# -- against a real cluster -------------------------------------------------


@pytest.fixture
def live_client():  # type: ignore[no-untyped-def]
    """Skip rather than error when the cluster named by the env var is down.

    Asking for live tests and getting a wall of connection errors tells you
    less than one clear skip line.
    """
    client = ElasticClient(LIVE_URL or "", timeout_s=20)
    try:
        client.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"NECROPSY_TEST_ELASTIC_URL is set but unreachable: {exc}")
    return client


def _seed(client, index: str, mapping: dict) -> datetime:  # type: ignore[no-untyped-def]
    now = datetime.now(timezone.utc)
    try:
        client._request("DELETE", f"/{index}")
    except Exception:  # noqa: BLE001
        pass
    client._request("PUT", f"/{index}", mapping)

    def doc(**kw):  # type: ignore[no-untyped-def]
        base = {"@timestamp": now.isoformat(), "winlog": {"channel": CHANNEL},
                "host": {"name": "WIN-LAB-01"}}
        base.update(kw)
        return base

    client.bulk_index(index, [
        doc(event={"code": "1"}, process={
            "executable": r"C:\Windows\System32\vssadmin.exe",
            "command_line": "vssadmin delete shadows /all /quiet"}),
        doc(event={"code": "1"}, process={
            "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell -nop -w hidden -enc SQBFAFgA"}),
        doc(event={"code": "13"}, registry={
            "path": r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\updater"}),
        doc(event={"code": "1"}, process={
            "executable": r"C:\Windows\System32\notepad.exe",
            "command_line": "notepad readme.txt"}),
    ])
    client._request("POST", f"/{index}/_refresh")
    return now


@live
def test_live_sweep_finds_the_planted_behaviour(live_client) -> None:  # type: ignore[no-untyped-def]
    index = "necropsy-test-sigma-ecs"
    now = _seed(live_client, index, ECS_MAPPING)

    result = sigma.run(live_client, index, _window(now))
    titles = {h.rule.title for h in result.hits}
    assert "Shadow Copy Deletion" in titles
    assert "Encoded PowerShell Command" in titles
    assert "Registry Run Key Persistence" in titles
    assert result.inconclusive is False
    assert "T1490" in result.summary()["techniques"]


@live
def test_live_benign_events_do_not_trip_rules(live_client) -> None:  # type: ignore[no-untyped-def]
    index = "necropsy-test-sigma-benign"
    now = datetime.now(timezone.utc)
    try:
        live_client._request("DELETE", f"/{index}")
    except Exception:  # noqa: BLE001
        pass
    live_client._request("PUT", f"/{index}", ECS_MAPPING)
    live_client.bulk_index(index, [{
        "@timestamp": now.isoformat(), "winlog": {"channel": CHANNEL},
        "host": {"name": "WIN-LAB-01"}, "event": {"code": "1"},
        "process": {"executable": r"C:\Windows\System32\notepad.exe",
                    "command_line": "notepad readme.txt"},
    }])
    live_client._request("POST", f"/{index}/_refresh")

    result = sigma.run(live_client, index, _window(now))
    assert result.hits == []
    # One benign event is still "we swept and saw nothing fire" -- flagged,
    # because it cannot be told apart from a mapping problem.
    assert result.inconclusive is True


@live
def test_live_text_mapped_index_is_reported_as_inconclusive(live_client) -> None:  # type: ignore[no-untyped-def]
    """The silent-zero case. It must never read as a clean sweep."""
    index = "necropsy-test-sigma-text"
    text_mapping = {
        "mappings": {"properties": {
            "@timestamp": {"type": "date"},
            "process": {"properties": {"executable": {"type": "text"},
                                       "command_line": {"type": "text"}}},
        }}
    }
    now = _seed(live_client, index, text_mapping)

    result = sigma.run(live_client, index, _window(now))
    assert result.hits == []
    assert result.inconclusive is True
    assert "does not have" in (result.note or "")


@live
def test_live_caseless_absence_is_detected_and_explained(live_client) -> None:  # type: ignore[no-untyped-def]
    index = "necropsy-test-sigma-ecs"
    now = _seed(live_client, index, ECS_MAPPING)
    result = sigma.run(live_client, index, _window(now))

    assert sigma.index_has_caseless(live_client, index) is False
    assert result.field_adaptation and "case-sensitive" in result.field_adaptation


@live
def test_live_empty_window_says_nothing_was_swept(live_client) -> None:  # type: ignore[no-untyped-def]
    index = "necropsy-test-sigma-empty"
    try:
        live_client._request("DELETE", f"/{index}")
    except Exception:  # noqa: BLE001
        pass
    live_client._request("PUT", f"/{index}", ECS_MAPPING)

    result = sigma.run(live_client, index, _window(datetime.now(timezone.utc)))
    assert result.inconclusive is True
    assert "no events at all" in (result.note or "")
