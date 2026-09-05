"""Sandbox endpoints -- the GUI's detonation timeline."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from necropsy.api.router import router
from tests.test_detonate import BUSY_EVENTS, FakeTarget

PREFIX = "/api/v1/necropsy"
CONFIRM = {"X-Necropsy-Confirm-Malware": "true"}


@pytest.fixture
def client(database, host):  # type: ignore[no-untyped-def]
    app = FastAPI()
    app.include_router(router, prefix=PREFIX)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def detonated(client: TestClient, monkeypatch: pytest.MonkeyPatch, loader_sample: Path) -> dict:
    import necropsy.sandbox.targets as targets_mod
    from necropsy.jobs.tasks import detonate as detonate_mod

    # Two seams, deliberately: the job builds the target, and the accept
    # endpoint independently re-checks that this install can actually run it.
    # Patching only the first would let the API refuse a run the test expects.
    monkeypatch.setattr(targets_mod, "build_target", lambda **_kw: FakeTarget())
    monkeypatch.setattr(detonate_mod, "build_target", lambda **_kw: FakeTarget())
    monkeypatch.setattr(
        detonate_mod, "_fetch_telemetry", lambda *a, **k: (BUSY_EVENTS, "fake telemetry")
    )

    case = client.post(f"{PREFIX}/cases", json={"name": "Detonation"}).json()
    client.post(
        f"{PREFIX}/cases/{case['id']}/samples",
        files={"file": ("loader.exe", loader_sample.read_bytes())},
        headers=CONFIRM,
    )
    actions = client.get(f"{PREFIX}/cases/{case['id']}/actions").json()
    detonate = next(a for a in actions if a["kind"] == "detonate" and not a["params"]["egress"])
    accepted = client.post(f"{PREFIX}/actions/{detonate['id']}/accept")
    assert accepted.status_code == 200, accepted.text
    return {"case": case, "job": accepted.json()["job_id"]}


def test_status_reports_why_detonation_is_unavailable(client: TestClient) -> None:
    status = client.get(f"{PREFIX}/sandbox/status").json()
    assert status["enabled"] is False
    assert status["ready"] is False
    assert "NECROPSY_SANDBOX_ENABLED" in status["reason"]
    assert status["known_targets"] == ["remote", "vmware"]
    assert status["elastic_ready"] is False


def test_detonation_is_listed_on_the_case(client: TestClient, detonated: dict) -> None:
    runs = client.get(f"{PREFIX}/cases/{detonated['case']['id']}/detonations").json()
    assert len(runs) == 1

    run = runs[0]
    assert run["state"] == "completed"
    assert run["reverted"] is True
    assert run["fidelity"] == "emulated"
    assert run["telemetry_events"] == len(BUSY_EVENTS)
    assert run["readable"] is True


def test_timeline_returns_the_raw_events(client: TestClient, detonated: dict) -> None:
    run = client.get(f"{PREFIX}/cases/{detonated['case']['id']}/detonations").json()[0]
    timeline = client.get(f"{PREFIX}/detonations/{run['id']}/timeline").json()

    assert timeline["event_count"] == len(BUSY_EVENTS)
    assert len(timeline["events"]) == len(BUSY_EVENTS)
    assert timeline["readable"] is True
    assert "autorun_persistence" in timeline["behaviours"]["behaviours"]


def test_findings_from_the_run_reach_the_case_timeline(
    client: TestClient, detonated: dict
) -> None:
    findings = client.get(f"{PREFIX}/cases/{detonated['case']['id']}/findings").json()
    behavioural = [f for f in findings if f["type"].startswith("behaviour:")]
    assert behavioural
    assert any("T1547.001" in f["attack_technique_ids"] for f in behavioural)
    assert all(f["producer"] == "sandbox" for f in behavioural)


def test_accepting_detonation_records_who_authorised_it(
    client: TestClient, detonated: dict
) -> None:
    """A named human authorised running live malware. That is the record."""
    actions = client.get(
        f"{PREFIX}/cases/{detonated['case']['id']}/actions?state=executed"
    ).json()
    executed = next(a for a in actions if a["kind"] == "detonate")
    assert executed["decided_by"] == "test.analyst"
    assert executed["decided_at"]


def test_unknown_detonation_is_404(client: TestClient) -> None:
    assert client.get(f"{PREFIX}/detonations/nope").status_code == 404
    assert client.get(f"{PREFIX}/detonations/nope/timeline").status_code == 404
