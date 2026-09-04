from __future__ import annotations

from pathlib import Path

from necropsy.cases import service as case_service
from necropsy.db.repos import jobs as jobs_repo
from necropsy.enums import JobKind
from necropsy.intake import service as intake


def _case(session, host, name):  # type: ignore[no-untyped-def]
    case = case_service.create_case(session, host, name=name)
    session.commit()
    return case


def test_double_enqueue_returns_one_job(session, host, pe_sample: Path) -> None:
    case = _case(session, host, "A")
    result = intake.ingest_file(session, host, case_id=case.id, src=pe_sample, enqueue=False)
    session.commit()

    first, created_a = jobs_repo.enqueue_or_get(
        session,
        case_id=case.id,
        kind=JobKind.IDENTIFY,
        sample_id=result.sample.id,
        sample_sha256=result.sample.sha256,
    )
    second, created_b = jobs_repo.enqueue_or_get(
        session,
        case_id=case.id,
        kind=JobKind.IDENTIFY,
        sample_id=result.sample.id,
        sample_sha256=result.sample.sha256,
    )
    assert created_a is True and created_b is False
    assert first.id == second.id


def test_same_sample_in_a_different_case_is_new_work(session, host, pe_sample: Path) -> None:
    """Findings are case-scoped, so identical bytes in a second case must analyse again."""
    case_a = _case(session, host, "A")
    case_b = _case(session, host, "B")
    result = intake.ingest_file(session, host, case_id=case_a.id, src=pe_sample, enqueue=False)
    intake.ingest_file(session, host, case_id=case_b.id, src=pe_sample, enqueue=False)
    session.commit()

    job_a, _ = jobs_repo.enqueue_or_get(
        session, case_id=case_a.id, kind=JobKind.IDENTIFY,
        sample_id=result.sample.id, sample_sha256=result.sample.sha256,
    )
    job_b, created = jobs_repo.enqueue_or_get(
        session, case_id=case_b.id, kind=JobKind.IDENTIFY,
        sample_id=result.sample.id, sample_sha256=result.sample.sha256,
    )
    assert created is True
    assert job_a.id != job_b.id


def test_different_params_are_different_work(session, host, pe_sample: Path) -> None:
    """An isolated detonation and an egress-permitted one are not the same job."""
    case = _case(session, host, "A")
    result = intake.ingest_file(session, host, case_id=case.id, src=pe_sample, enqueue=False)
    session.commit()

    isolated, _ = jobs_repo.enqueue_or_get(
        session, case_id=case.id, kind=JobKind.DETONATE,
        sample_id=result.sample.id, sample_sha256=result.sample.sha256,
        params={"egress": False},
    )
    egress, created = jobs_repo.enqueue_or_get(
        session, case_id=case.id, kind=JobKind.DETONATE,
        sample_id=result.sample.id, sample_sha256=result.sample.sha256,
        params={"egress": True},
    )
    assert created is True
    assert isolated.id != egress.id


def test_param_ordering_does_not_change_the_key() -> None:
    a = jobs_repo.idempotency_key(
        case_id="c", sample_sha256="a" * 64, kind=JobKind.DETONATE,
        params={"egress": True, "timeout": 60},
    )
    b = jobs_repo.idempotency_key(
        case_id="c", sample_sha256="a" * 64, kind=JobKind.DETONATE,
        params={"timeout": 60, "egress": True},
    )
    assert a == b
