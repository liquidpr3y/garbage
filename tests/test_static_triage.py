"""Static triage end to end: the Phase 2 pipeline proved through the job."""

from __future__ import annotations

from pathlib import Path

import pytest

from necropsy.analysis import artifacts as artifact_store
from necropsy.cases import service as case_service
from necropsy.db.repos import actions as actions_repo, findings as findings_repo
from necropsy.db.repos import jobs as jobs_repo, samples as samples_repo
from necropsy.enums import ArtifactKind, JobKind, JobState, Producer
from necropsy.intake import service as intake
from necropsy.jobs.tasks.base import execute_job


def _triage(session, host, src: Path, *, name="Triage", allow_ai=False):  # type: ignore[no-untyped-def]
    case = case_service.create_case(session, host, name=name, ai_disclosure_allowed=allow_ai)
    session.commit()
    result = intake.ingest_file(session, host, case_id=case.id, src=src)
    session.commit()
    execute_job(result.job_id)

    job, _ = jobs_repo.enqueue_or_get(
        session, case_id=case.id, kind=JobKind.STATIC_TRIAGE,
        sample_id=result.sample.id, sample_sha256=result.sample.sha256,
    )
    session.commit()
    execute_job(job.id)
    session.expire_all()
    return case, result.sample, jobs_repo.get(session, job.id)


def test_triage_succeeds_and_summarises(session, host, loader_sample: Path) -> None:
    _case, _sample, job = _triage(session, host, loader_sample)
    assert job.state is JobState.SUCCEEDED, job.error

    summary = job.result_summary
    assert summary["imports"] == 12
    assert summary["imphash"]
    assert summary["strings"] > 20
    assert "process_injection" in summary["capabilities"]


def test_findings_carry_attack_techniques(session, host, loader_sample: Path) -> None:
    """Phase 2 tags at the producer; Phase 4 aggregates. The columns fill now."""
    case, _sample, _job = _triage(session, host, loader_sample)
    findings = findings_repo.for_case(session, case.id)

    tagged = [f for f in findings if f.attack_technique_ids]
    assert len(tagged) >= 6
    techniques = {t for f in findings for t in f.attack_technique_ids}
    assert {"T1055", "T1547.001", "T1490", "T1497.001"} <= techniques
    assert all(f.kill_chain_phase for f in tagged if f.producer is Producer.CAPABILITY)


def test_pe_structural_findings(session, host, loader_sample: Path) -> None:
    case, _sample, _job = _triage(session, host, loader_sample)
    types = {f.type for f in findings_repo.for_case(session, case.id)}
    assert "pe_writable_executable_section" in types
    assert "pe_tls_callbacks" in types
    assert "pe_debug_path" in types


def test_yara_and_ioc_findings(session, host, loader_sample: Path) -> None:
    case, _sample, _job = _triage(session, host, loader_sample)
    findings = findings_repo.for_case(session, case.id)
    types = {f.type for f in findings}

    assert any(t.startswith("yara:") for t in types)
    assert "network_iocs" in types
    iocs = next(f for f in findings if f.type == "network_iocs")
    assert "185.220.101.44" in iocs.evidence.get("ipv4", [])


def test_a_plain_binary_stays_quiet(session, host, plain_sample: Path) -> None:
    """The true-negative case. A triage tool that flags everything is noise."""
    case, _sample, job = _triage(session, host, plain_sample)
    assert job.state is JobState.SUCCEEDED

    findings = findings_repo.for_case(session, case.id)
    serious = [f for f in findings if f.severity.value in ("high", "critical")]
    assert serious == [], [f.type for f in serious]
    assert not [f for f in findings if f.type.startswith("capability:")]


def test_artifacts_are_vaulted(session, host, loader_sample: Path) -> None:
    case, sample, _job = _triage(session, host, loader_sample)

    strings_artifact = artifact_store.latest(session, sample.id, ArtifactKind.STRINGS)
    report_artifact = artifact_store.latest(session, sample.id, ArtifactKind.STATIC_REPORT)
    assert strings_artifact and report_artifact

    vault = intake.open_vault(session, actor="t")
    assert vault.exists(strings_artifact.sha256)
    # Derived artifacts get the same handling as samples: encrypted, 0o400.
    assert vault.path_for(strings_artifact.sha256).stat().st_mode & 0o777 == 0o400

    payload = artifact_store.load_json(
        session, report_artifact, actor="t", case_id=case.id
    )
    assert payload["pe"]["imphash"]
    assert payload["detection_quality"]["import_count"] == 12


def test_triage_proposes_a_decompile(session, host, loader_sample: Path) -> None:
    case, _sample, _job = _triage(session, host, loader_sample)
    kinds = {a.kind for a in actions_repo.for_case(session, case.id)}
    assert "ghidra_decompile" in kinds
    assert "yara_scan" in kinds
    assert "detonate" in kinds


def test_rerunning_triage_does_not_multiply_findings(
    session, host, loader_sample: Path
) -> None:
    case, sample, _job = _triage(session, host, loader_sample)
    before = len(findings_repo.for_case(session, case.id))

    job, _ = jobs_repo.enqueue_or_get(
        session, case_id=case.id, kind=JobKind.STATIC_TRIAGE,
        sample_id=sample.id, sample_sha256=sample.sha256, params={"rerun": 1},
    )
    session.commit()
    execute_job(job.id)
    session.expire_all()
    assert len(findings_repo.for_case(session, case.id)) == before


def test_imphash_is_recorded_on_the_sample(session, host, loader_sample: Path) -> None:
    _case, sample, _job = _triage(session, host, loader_sample)
    session.refresh(sample)
    assert sample.identity["imphash"]
    assert sample.identity["static"]["pe"]["import_count"] == 12


def test_yara_scan_job_runs_standalone(session, host, loader_sample: Path) -> None:
    case, sample, _job = _triage(session, host, loader_sample)
    job, _ = jobs_repo.enqueue_or_get(
        session, case_id=case.id, kind=JobKind.YARA_SCAN,
        sample_id=sample.id, sample_sha256=sample.sha256,
    )
    session.commit()
    execute_job(job.id)
    session.expire_all()

    done = jobs_repo.get(session, job.id)
    assert done.state is JobState.SUCCEEDED
    assert done.result_summary["hit_count"] >= 1
