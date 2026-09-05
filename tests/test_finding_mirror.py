"""Mirroring findings into Elastic.

SQLite stays the system of record; this is a best-effort copy so a hunter can
pivot in Kibana. Every test here is about that being true even when the
cluster misbehaves.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from necropsy.db.models import Finding
from necropsy.elastic.client import ElasticClient
from necropsy.enums import KillChainPhase, Producer, Severity
from necropsy.sinks.base import NullSink, to_ecs
from necropsy.sinks.elastic import DATA_STREAM, ElasticFindingSink

LIVE_URL = os.environ.get("NECROPSY_TEST_ELASTIC_URL")
live = pytest.mark.skipif(not LIVE_URL, reason="set NECROPSY_TEST_ELASTIC_URL to run")


def make_finding(**kw) -> Finding:  # type: ignore[no-untyped-def]
    defaults = dict(
        id="f-1", case_id="c-1", sample_id="s-1", job_id="j-1",
        producer=Producer.SANDBOX, type="behaviour:autorun_persistence",
        title="Wrote an autorun registry value", description="persistence established",
        severity=Severity.HIGH, confidence=0.95,
        attack_technique_ids=["T1547.001"], kill_chain_phase=KillChainPhase.INSTALLATION,
        evidence={"paths": ["HKCU\\...\\Run\\x"]}, dedupe_key="k",
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(kw)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_ecs_threat_block_uses_attack_tactics_not_kill_chain_phases() -> None:
    """ECS threat.* is ATT&CK's namespace; putting our kill chain there would
    look right and break every Kibana ATT&CK view that reads it."""
    doc = to_ecs(make_finding())
    assert doc["threat"]["framework"] == "MITRE ATT&CK"
    assert doc["threat"]["technique"]["id"] == ["T1547.001"]
    assert doc["threat"]["technique"]["name"] == ["Registry Run Keys / Startup Folder"]
    assert "Persistence" in doc["threat"]["tactic"]["name"]
    assert "TA0003" in doc["threat"]["tactic"]["id"]
    # The kill chain view lives in our own namespace.
    assert doc["necropsy"]["kill_chain_phase"] == "installation"


def test_ecs_document_carries_the_pivot_keys() -> None:
    doc = to_ecs(make_finding())
    assert doc["necropsy"]["case_id"] == "c-1"
    assert doc["necropsy"]["finding_id"] == "f-1"
    assert doc["event"]["kind"] == "signal"
    assert doc["event"]["severity"] == 7
    assert doc["message"] == "Wrote an autorun registry value"


def test_revoked_technique_is_mirrored_as_its_replacement() -> None:
    doc = to_ecs(make_finding(attack_technique_ids=["T1562.001"]))
    assert doc["threat"]["technique"]["id"] == ["T1685"]


def test_a_finding_with_no_technique_has_no_threat_block() -> None:
    doc = to_ecs(make_finding(attack_technique_ids=[]))
    assert "threat" not in doc


def test_null_sink_is_the_default_and_never_fails() -> None:
    assert NullSink().emit(make_finding()) is None


def test_an_unreachable_cluster_returns_none_rather_than_raising() -> None:
    """A SIEM outage costs the mirror, never the finding."""
    sink = ElasticFindingSink(ElasticClient("http://127.0.0.1:9", timeout_s=2))
    assert sink.emit(make_finding()) is None


@pytest.fixture
def live_sink():  # type: ignore[no-untyped-def]
    client = ElasticClient(LIVE_URL or "", timeout_s=20)
    client.ping()
    for path in (f"/_data_stream/{DATA_STREAM}", "/_index_template/necropsy-findings"):
        try:
            client._request("DELETE", path)
        except Exception:  # noqa: BLE001
            pass
    return ElasticFindingSink(client), client


@live
def test_live_mirror_creates_the_stream_and_indexes(live_sink) -> None:  # type: ignore[no-untyped-def]
    sink, client = live_sink
    assert sink.emit(make_finding()) == "f-1"
    client._request("POST", f"/{DATA_STREAM}/_refresh")

    result = client.search(DATA_STREAM, {"query": {"match_all": {}}})
    assert result.total == 1


@live
def test_live_pivot_by_technique_and_case(live_sink) -> None:  # type: ignore[no-untyped-def]
    """The point of the mirror: these queries work in Kibana."""
    sink, client = live_sink
    sink.emit(make_finding(id="f-a", attack_technique_ids=["T1547.001"]))
    sink.emit(make_finding(id="f-b", case_id="c-2", attack_technique_ids=["T1490"]))
    client._request("POST", f"/{DATA_STREAM}/_refresh")

    by_technique = client.search(
        DATA_STREAM, {"query": {"term": {"threat.technique.id": "T1547.001"}}}
    )
    assert by_technique.total == 1

    by_case = client.search(DATA_STREAM, {"query": {"term": {"necropsy.case_id": "c-2"}}})
    assert by_case.total == 1

    by_tactic = client.search(
        DATA_STREAM, {"query": {"term": {"threat.tactic.name": "Impact"}}}
    )
    assert by_tactic.total == 1


@live
def test_live_bulk_mirror(live_sink) -> None:  # type: ignore[no-untyped-def]
    sink, client = live_sink
    findings = [make_finding(id=f"f-{i}", dedupe_key=f"k{i}") for i in range(20)]
    indexed, errors = sink.emit_many(findings)
    assert indexed == 20 and not errors
