"""End-to-end through the router the GUI panel binds to."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from necropsy.api.router import router

PREFIX = "/api/v1/necropsy"
CONFIRM = {"X-Necropsy-Confirm-Malware": "true"}


@pytest.fixture
def client(database, host):  # type: ignore[no-untyped-def]
    app = FastAPI()
    app.include_router(router, prefix=PREFIX)
    with TestClient(app) as c:
        yield c


def _new_case(client: TestClient, **kw) -> dict:  # type: ignore[no-untyped-def]
    body = {"name": "Phishing wave", "severity": "medium", "tags": ["phish"], **kw}
    response = client.post(f"{PREFIX}/cases", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def test_health(client: TestClient) -> None:
    assert client.get(f"{PREFIX}/health").json()["module"] == "necropsy"


def test_case_lifecycle(client: TestClient) -> None:
    case = _new_case(client)
    assert case["ai_disclosure_allowed"] is False

    listed = client.get(f"{PREFIX}/cases").json()
    assert [c["id"] for c in listed] == [case["id"]]

    detail = client.get(f"{PREFIX}/cases/{case['id']}").json()
    assert detail["counts"] == {"samples": 0, "jobs": 0, "findings": 0, "open_actions": 0}

    closed = client.patch(f"{PREFIX}/cases/{case['id']}", json={"status": "closed"}).json()
    assert closed["status"] == "closed"
    assert client.get(f"{PREFIX}/cases?status=open").json() == []


def test_ingest_requires_the_confirmation_header(client: TestClient, pe_sample: Path) -> None:
    case = _new_case(client)
    response = client.post(
        f"{PREFIX}/cases/{case['id']}/samples",
        files={"file": ("invoice.exe", pe_sample.read_bytes())},
    )
    assert response.status_code == 428
    assert "X-Necropsy-Confirm-Malware" in response.json()["detail"]


def test_upload_runs_the_full_pipeline(client: TestClient, x86_packed_sample: Path) -> None:
    case = _new_case(client)
    response = client.post(
        f"{PREFIX}/cases/{case['id']}/samples",
        files={"file": ("packed.exe", x86_packed_sample.read_bytes())},
        headers=CONFIRM,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["new_to_platform"] is True
    assert body["identify_job_id"]

    job = client.get(f"{PREFIX}/jobs/{body['identify_job_id']}").json()
    assert job["state"] == "succeeded"
    assert job["result_summary"]["arch"] == "x86"

    findings = client.get(f"{PREFIX}/cases/{case['id']}/findings").json()
    types = {f["type"] for f in findings}
    assert {"high_entropy", "arch_mismatch_risk"} <= types
    # ATT&CK columns exist on the wire from Phase 1, empty until Phase 4.
    assert all("attack_technique_ids" in f for f in findings)

    actions = client.get(f"{PREFIX}/cases/{case['id']}/actions").json()
    assert len(actions) >= 2
    assert all(a["risk_band"] for a in actions)

    detail = client.get(f"{PREFIX}/cases/{case['id']}").json()
    assert detail["counts"]["samples"] == 1
    assert detail["counts"]["findings"] == len(findings)


def test_ingest_by_path(client: TestClient, pe_sample: Path) -> None:
    case = _new_case(client)
    response = client.post(
        f"{PREFIX}/cases/{case['id']}/samples/by-path",
        json={"path": str(pe_sample)},
        headers=CONFIRM,
    )
    assert response.status_code == 201, response.text
    assert response.json()["sample"]["file_type"] == "pe"


def test_sample_detail_exposes_the_cross_case_pivot(client: TestClient, pe_sample: Path) -> None:
    case_a = _new_case(client, name="First")
    case_b = _new_case(client, name="Second")
    for case in (case_a, case_b):
        client.post(
            f"{PREFIX}/cases/{case['id']}/samples",
            files={"file": ("invoice.exe", pe_sample.read_bytes())},
            headers=CONFIRM,
        )

    sha = client.get(f"{PREFIX}/cases/{case_a['id']}/samples").json()[0]["sample"]["sha256"]
    detail = client.get(f"{PREFIX}/samples/{sha}").json()
    assert {c["name"] for c in detail["other_cases"]} == {"First", "Second"}


def test_accepting_a_proposal_enqueues_and_records_the_decision(
    client: TestClient, pe_sample: Path
) -> None:
    case = _new_case(client)
    client.post(
        f"{PREFIX}/cases/{case['id']}/samples",
        files={"file": ("invoice.exe", pe_sample.read_bytes())},
        headers=CONFIRM,
    )
    actions = client.get(f"{PREFIX}/cases/{case['id']}/actions").json()
    pivot = next(a for a in actions if a["kind"] == "hash_pivot")

    response = client.post(f"{PREFIX}/actions/{pivot['id']}/accept", json={"note": "triage"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["job_id"]
    assert body["action"]["decided_by"] == "test.analyst"
    assert body["action"]["decided_at"]

    assert client.get(f"{PREFIX}/jobs/{body['job_id']}").json()["state"] == "succeeded"
    # An accepted proposal becomes executed once its job lands.
    executed = client.get(f"{PREFIX}/cases/{case['id']}/actions?state=executed").json()
    assert pivot["id"] in {a["id"] for a in executed}


def test_accepting_an_unimplemented_proposal_is_refused_clearly(
    client: TestClient, pe_sample: Path
) -> None:
    case = _new_case(client)
    client.post(
        f"{PREFIX}/cases/{case['id']}/samples",
        files={"file": ("invoice.exe", pe_sample.read_bytes())},
        headers=CONFIRM,
    )
    actions = client.get(f"{PREFIX}/cases/{case['id']}/actions").json()
    detonate = next(a for a in actions if a["kind"] == "detonate")

    response = client.post(f"{PREFIX}/actions/{detonate['id']}/accept")
    assert response.status_code == 409
    assert "Phase 3" in response.json()["detail"]


def test_ai_summarise_is_blocked_without_case_consent(
    client: TestClient, pe_sample: Path
) -> None:
    """The per-case disclosure gate, enforced at the point of decision."""
    case = _new_case(client, ai_disclosure_allowed=False)
    client.post(
        f"{PREFIX}/cases/{case['id']}/samples",
        files={"file": ("invoice.exe", pe_sample.read_bytes())},
        headers=CONFIRM,
    )
    actions = client.get(f"{PREFIX}/cases/{case['id']}/actions").json()
    ai = next(a for a in actions if a["kind"] == "ai_summarise")

    response = client.post(f"{PREFIX}/actions/{ai['id']}/accept")
    assert response.status_code == 403
    assert "ai_disclosure_allowed" in response.json()["detail"]


def test_rejecting_a_proposal(client: TestClient, pe_sample: Path) -> None:
    case = _new_case(client)
    client.post(
        f"{PREFIX}/cases/{case['id']}/samples",
        files={"file": ("invoice.exe", pe_sample.read_bytes())},
        headers=CONFIRM,
    )
    actions = client.get(f"{PREFIX}/cases/{case['id']}/actions").json()
    target = actions[0]

    body = client.post(
        f"{PREFIX}/actions/{target['id']}/reject", json={"note": "out of scope"}
    ).json()
    assert body["state"] == "rejected"
    assert body["decision_note"] == "out of scope"
    assert client.post(f"{PREFIX}/actions/{target['id']}/accept").status_code == 409


def test_timeline_merges_every_kind_of_event(client: TestClient, pe_sample: Path) -> None:
    case = _new_case(client)
    client.post(
        f"{PREFIX}/cases/{case['id']}/samples",
        files={"file": ("invoice.exe", pe_sample.read_bytes())},
        headers=CONFIRM,
    )
    timeline = client.get(f"{PREFIX}/cases/{case['id']}/timeline").json()
    kinds = {entry["kind"] for entry in timeline}
    assert {"job", "finding", "action", "audit"} <= kinds

    # The vault read during identification is part of the chain of custody.
    audit_titles = {e["title"] for e in timeline if e["kind"] == "audit"}
    assert {"sample.ingested", "vault.write", "vault.read"} <= audit_titles


def test_unknown_ids_are_404(client: TestClient) -> None:
    for path in ("/cases/nope", "/cases/nope/findings", "/jobs/nope", "/samples/" + "a" * 64):
        assert client.get(PREFIX + path).status_code == 404
