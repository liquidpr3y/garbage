"""The identify job is where Phase 1's pipeline is proved end to end."""

from __future__ import annotations

from pathlib import Path

from necropsy.cases import service as case_service
from necropsy.contracts.events import EventType
from necropsy.db.repos import actions as actions_repo, findings as findings_repo, jobs as jobs_repo
from necropsy.enums import ActionState, Arch, FileType, JobKind, JobState
from necropsy.intake import service as intake
from necropsy.jobs.tasks.base import execute_job


def _ingest(session, host, src: Path, *, name="Case", allow_ai=False):  # type: ignore[no-untyped-def]
    case = case_service.create_case(session, host, name=name, ai_disclosure_allowed=allow_ai)
    session.commit()
    result = intake.ingest_file(session, host, case_id=case.id, src=src)
    session.commit()
    execute_job(result.job_id)
    session.expire_all()
    return case, result


def test_identify_job_updates_the_sample(session, host, pe_sample: Path) -> None:
    case, result = _ingest(session, host, pe_sample)
    job = jobs_repo.get(session, result.job_id)
    assert job.state is JobState.SUCCEEDED

    session.refresh(result.sample)
    assert result.sample.file_type is FileType.PE
    assert result.sample.arch is Arch.X86_64
    assert result.sample.entropy is not None


def test_x86_sample_on_arm_lab_gets_a_fidelity_warning(
    session, host, x86_packed_sample: Path
) -> None:
    """The finding that stops a dormant emulated run being read as 'clean'."""
    case, _ = _ingest(session, host, x86_packed_sample)
    types = {f.type for f in findings_repo.for_case(session, case.id)}
    assert "arch_mismatch_risk" in types
    assert "high_entropy" in types

    warning = next(
        f for f in findings_repo.for_case(session, case.id) if f.type == "arch_mismatch_risk"
    )
    assert "dormancy" in warning.description.lower()
    assert warning.evidence["target_arches"] == ["arm64"]


def test_arm64_sample_gets_no_mismatch_warning(session, host, tmp_path: Path) -> None:
    from conftest import make_pe

    case, _ = _ingest(session, host, make_pe(tmp_path / "native.exe", machine=0xAA64))
    types = {f.type for f in findings_repo.for_case(session, case.id)}
    assert "arch_mismatch_risk" not in types


def test_macro_doc_is_flagged_and_not_arch_constrained(session, host, macro_doc: Path) -> None:
    case, _ = _ingest(session, host, macro_doc)
    types = {f.type for f in findings_repo.for_case(session, case.id)}
    assert "office_vba_macro" in types
    assert "arch_mismatch_risk" not in types


def test_second_case_gets_a_reappearance_finding(session, host, pe_sample: Path) -> None:
    _ingest(session, host, pe_sample, name="First")
    case_b, _ = _ingest(session, host, pe_sample, name="Second")
    types = {f.type for f in findings_repo.for_case(session, case_b.id)}
    assert "known_sample_reappearance" in types


def test_proposals_are_risk_scored_and_ordered(session, host, x86_packed_sample: Path) -> None:
    case, _ = _ingest(session, host, x86_packed_sample)
    proposals = actions_repo.for_case(session, case.id)
    assert len(proposals) >= 2

    by_kind = {p.kind: p for p in proposals}
    # An isolated detonation must always score below an egress-permitted one.
    isolated = next(p for p in proposals if p.kind == "detonate" and not p.params["egress"])
    egress = next(p for p in proposals if p.kind == "detonate" and p.params["egress"])
    assert egress.risk_score > isolated.risk_score

    # Reading a file is not comparable in blast radius to running it.
    assert by_kind["hash_pivot"].risk_score < isolated.risk_score
    assert all(p.risk_factors for p in (isolated, egress))
    assert sorted((p.risk_score for p in proposals), reverse=True) == [
        p.risk_score for p in proposals
    ]


def test_unavailable_kinds_are_offered_but_marked_so(session, host, pe_sample: Path) -> None:
    """The whole decision space is shown; what cannot run says why."""
    case, _ = _ingest(session, host, pe_sample)
    proposals = {p.kind: p for p in actions_repo.for_case(session, case.id)}

    # Implemented, but this machine has no Anthropic credentials.
    assert proposals["ai_summarise"].available is False
    reason = proposals["ai_summarise"].unavailable_reason
    assert "credentials" in reason or "anthropic SDK" in reason
    assert "Phase 5" not in reason

    # Detonation is built, but this install has no sandbox configured -- a
    # different reason, and the operator should be told which.
    assert proposals["detonate"].available is False
    assert "sandbox" in proposals["detonate"].unavailable_reason.lower()

    assert proposals["hash_pivot"].available is True


def test_rerunning_identify_supersedes_stale_proposals(session, host, pe_sample: Path) -> None:
    case, result = _ingest(session, host, pe_sample)
    first = actions_repo.for_case(session, case.id)

    job, _ = jobs_repo.enqueue_or_get(
        session,
        case_id=case.id,
        kind=JobKind.IDENTIFY,
        sample_id=result.sample.id,
        sample_sha256=result.sample.sha256,
        params={"rerun": 1},
    )
    session.commit()
    execute_job(job.id)
    session.expire_all()

    open_now = actions_repo.for_case(session, case.id, state=ActionState.PROPOSED)
    expired = actions_repo.for_case(session, case.id, state=ActionState.EXPIRED)
    assert len(open_now) == len(first)
    assert len(expired) == len(first)


def test_findings_are_deduped_not_multiplied(session, host, x86_packed_sample: Path) -> None:
    case, result = _ingest(session, host, x86_packed_sample)
    before = len(findings_repo.for_case(session, case.id))

    job, _ = jobs_repo.enqueue_or_get(
        session,
        case_id=case.id,
        kind=JobKind.IDENTIFY,
        sample_id=result.sample.id,
        sample_sha256=result.sample.sha256,
        params={"rerun": 2},
    )
    session.commit()
    execute_job(job.id)
    session.expire_all()
    assert len(findings_repo.for_case(session, case.id)) == before


def test_events_reach_subscribers(session, host, pe_sample: Path) -> None:
    _ingest(session, host, pe_sample)
    types = {e.type for _, e in host.events}
    assert EventType.SAMPLE_INGESTED in types
    assert EventType.JOB_STARTED in types
    assert EventType.JOB_SUCCEEDED in types
    assert EventType.FINDING_CREATED in types
    assert EventType.ACTION_PROPOSED in types


def test_job_failure_is_recorded_not_raised(session, host, pe_sample: Path) -> None:
    """A vanished vault object must fail the job, not kill the worker."""
    case, result = _ingest(session, host, pe_sample)
    vault = intake.open_vault(session, actor="t")
    target = vault.path_for(result.sample.sha256)
    target.chmod(0o600)
    target.unlink()

    job, _ = jobs_repo.enqueue_or_get(
        session,
        case_id=case.id,
        kind=JobKind.IDENTIFY,
        sample_id=result.sample.id,
        sample_sha256=result.sample.sha256,
        params={"rerun": 3},
    )
    session.commit()
    execute_job(job.id)
    session.expire_all()

    failed = jobs_repo.get(session, job.id)
    assert failed.state is JobState.FAILED
    assert "not in vault" in failed.error


def test_hash_pivot_finds_the_other_case(session, host, pe_sample: Path) -> None:
    _ingest(session, host, pe_sample, name="First")
    case_b, result = _ingest(session, host, pe_sample, name="Second")

    job, _ = jobs_repo.enqueue_or_get(
        session,
        case_id=case_b.id,
        kind=JobKind.HASH_PIVOT,
        sample_id=result.sample.id,
        sample_sha256=result.sample.sha256,
    )
    session.commit()
    execute_job(job.id)
    session.expire_all()

    done = jobs_repo.get(session, job.id)
    assert done.state is JobState.SUCCEEDED
    assert done.result_summary["exact_matches"] == 1
    assert "exact_hash_match" in {f.type for f in findings_repo.for_case(session, case_b.id)}
