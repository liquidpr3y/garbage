"""The endpoints the GUI's static-analysis panel binds to."""

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


@pytest.fixture
def triaged(client: TestClient, loader_sample: Path) -> dict:
    case = client.post(f"{PREFIX}/cases", json={"name": "Loader"}).json()
    ingest = client.post(
        f"{PREFIX}/cases/{case['id']}/samples",
        files={"file": ("loader.exe", loader_sample.read_bytes())},
        headers=CONFIRM,
    ).json()

    actions = client.get(f"{PREFIX}/cases/{case['id']}/actions").json()
    triage = next(a for a in actions if a["kind"] == "static_triage")
    accepted = client.post(f"{PREFIX}/actions/{triage['id']}/accept")
    assert accepted.status_code == 200, accepted.text
    return {"case": case, "sha256": ingest["sample"]["sha256"], "job": accepted.json()["job_id"]}


def test_static_triage_is_reachable_by_accepting_a_proposal(
    client: TestClient, triaged: dict
) -> None:
    """Phase 1's human-in-the-loop now drives real Phase 2 work."""
    job = client.get(f"{PREFIX}/jobs/{triaged['job']}").json()
    assert job["state"] == "succeeded"
    assert "process_injection" in job["result_summary"]["capabilities"]


def test_static_report_endpoint(client: TestClient, triaged: dict) -> None:
    report = client.get(f"{PREFIX}/samples/{triaged['sha256']}/static").json()
    assert report["pe"]["import_count"] == 12
    assert report["pe"]["imphash"]
    assert any(c["capability"] == "process_injection" for c in report["capabilities"])
    assert "detection_quality" in report


def test_strings_endpoint_filters(client: TestClient, triaged: dict) -> None:
    sha = triaged["sha256"]
    everything = client.get(f"{PREFIX}/samples/{sha}/strings").json()
    assert everything["summary"]["total_unique"] > 20
    assert "185.220.101.44" in everything["iocs"]["ipv4"]

    filtered = client.get(f"{PREFIX}/samples/{sha}/strings?contains=vssadmin").json()
    assert filtered["matched"] >= 1
    assert all("vssadmin" in s.lower() for s in filtered["strings"])


def test_static_endpoints_404_before_triage(client: TestClient, pe_sample: Path) -> None:
    case = client.post(f"{PREFIX}/cases", json={"name": "Untriaged"}).json()
    ingest = client.post(
        f"{PREFIX}/cases/{case['id']}/samples",
        files={"file": ("x.exe", pe_sample.read_bytes())},
        headers=CONFIRM,
    ).json()
    response = client.get(f"{PREFIX}/samples/{ingest['sample']['sha256']}/static")
    assert response.status_code == 404
    assert "static triage" in response.json()["detail"]


def test_function_endpoints_are_empty_before_a_decompile(
    client: TestClient, triaged: dict
) -> None:
    sha = triaged["sha256"]
    assert client.get(f"{PREFIX}/samples/{sha}/functions").json() == []
    assert client.get(f"{PREFIX}/samples/{sha}/function-stats").json()["total"] == 0


def test_tooling_status_reports_what_is_installed(client: TestClient) -> None:
    status = client.get(f"{PREFIX}/analysis/tooling").json()
    assert set(status) >= {"lief", "yara", "tlsh", "libmagic", "rizin", "ghidra"}
    assert isinstance(status["ghidra"], bool)
    assert any(s["packaged"] for s in status["yara_rule_sources"])


def test_capability_catalogue_is_served_with_attack_ids(client: TestClient) -> None:
    catalogue = client.get(f"{PREFIX}/analysis/capabilities").json()
    assert len(catalogue) >= 20
    assert all(c["attack_technique_ids"] for c in catalogue)
    injection = next(c for c in catalogue if c["id"] == "process_injection")
    assert "T1055" in injection["attack_technique_ids"]
    assert injection["kill_chain_phase"]


def test_unknown_sample_and_function_are_404(client: TestClient) -> None:
    assert client.get(f"{PREFIX}/samples/{'a' * 64}/static").status_code == 404
    assert client.get(f"{PREFIX}/functions/nope").status_code == 404


def test_timeline_shows_the_triage_findings(client: TestClient, triaged: dict) -> None:
    timeline = client.get(f"{PREFIX}/cases/{triaged['case']['id']}/timeline").json()
    findings = [e for e in timeline if e["kind"] == "finding"]
    assert any(e["attack_technique_ids"] for e in findings)
    # The vault reads performed by triage are in the chain of custody.
    audit = {e["title"] for e in timeline if e["kind"] == "audit"}
    assert "vault.read" in audit
