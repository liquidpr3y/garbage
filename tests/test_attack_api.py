"""ATT&CK endpoints -- what the GUI heatmap binds to."""

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
def triaged_case(client: TestClient, loader_sample: Path) -> str:
    case = client.post(f"{PREFIX}/cases", json={"name": "Heatmap"}).json()
    client.post(
        f"{PREFIX}/cases/{case['id']}/samples",
        files={"file": ("loader.exe", loader_sample.read_bytes())},
        headers=CONFIRM,
    )
    actions = client.get(f"{PREFIX}/cases/{case['id']}/actions").json()
    triage = next(a for a in actions if a["kind"] == "static_triage")
    assert client.post(f"{PREFIX}/actions/{triage['id']}/accept").status_code == 200
    return case["id"]


def test_status_reports_the_bundled_taxonomy(client: TestClient) -> None:
    status = client.get(f"{PREFIX}/attack/status").json()
    assert status["technique_count"] > 600
    assert status["tactic_count"] >= 14
    assert status["attack_version"] != "unknown"
    assert isinstance(status["sigma_available"], bool)


def test_tactics_carry_their_kill_chain_mapping(client: TestClient) -> None:
    payload = client.get(f"{PREFIX}/attack/tactics").json()
    tactics = {t["shortname"]: t for t in payload["tactics"]}
    assert tactics["persistence"]["kill_chain_phase"] == "installation"
    assert tactics["command-and-control"]["kill_chain_phase"] == "command_and_control"
    # The models are not equivalent and the API says so rather than implying it.
    assert "not a MITRE-published equivalence" in payload["kill_chain_note"]


def test_technique_detail(client: TestClient) -> None:
    technique = client.get(f"{PREFIX}/attack/techniques/T1055").json()
    assert technique["name"] == "Process Injection"
    assert technique["subtechniques"]
    assert technique["sysmon_event_codes"]
    assert technique["url"].endswith("/T1055")

    assert client.get(f"{PREFIX}/attack/techniques/T9999").status_code == 404


def test_case_heatmap_is_built_from_real_findings(client: TestClient, triaged_case: str) -> None:
    coverage = client.get(f"{PREFIX}/cases/{triaged_case}/attack").json()
    assert coverage["technique_count"] > 0

    tactics = {t["shortname"] for t in coverage["tactics"]}
    assert "persistence" in tactics

    techniques = {
        cell["id"] for tactic in coverage["tactics"] for cell in tactic["techniques"]
    }
    assert "T1055" in techniques
    assert "T1547" in techniques


def test_heatmap_marks_static_findings_as_inferred(client: TestClient, triaged_case: str) -> None:
    coverage = client.get(f"{PREFIX}/cases/{triaged_case}/attack").json()
    cells = [c for t in coverage["tactics"] for c in t["techniques"]]
    assert all(c["evidence_grade"] == "inferred" for c in cells)
    assert coverage["observed_count"] == 0
    assert any("equipped to" in n for n in coverage["notes"])


def test_heatmap_reports_detection_gaps(client: TestClient, triaged_case: str) -> None:
    coverage = client.get(
        f"{PREFIX}/cases/{triaged_case}/attack?sysmon_codes=1,3"
    ).json()
    assert coverage["detection_gaps"]
    gap = coverage["detection_gaps"][0]
    assert gap["missing_sysmon_codes"]
    assert set(gap["missing_sysmon_codes"]).isdisjoint({"1", "3"})


def test_kill_chain_view_accompanies_the_matrix(client: TestClient, triaged_case: str) -> None:
    coverage = client.get(f"{PREFIX}/cases/{triaged_case}/attack").json()
    assert coverage["kill_chain"]
    assert coverage["kill_chain_note"]


def test_sigma_rules_are_listed(client: TestClient) -> None:
    payload = client.get(f"{PREFIX}/attack/sigma/rules").json()
    if not payload["available"]:
        pytest.skip("pySigma not installed")
    assert len(payload["rules"]) >= 8
    assert all(r["attack_techniques"] for r in payload["rules"])


def test_unknown_case_is_404(client: TestClient) -> None:
    assert client.get(f"{PREFIX}/cases/nope/attack").status_code == 404
