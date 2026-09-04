from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from necropsy.db.models import AnalysisJob
from necropsy.enums import JobKind, JobState


def idempotency_key(
    *, case_id: str, sample_sha256: str | None, kind: JobKind, params: dict[str, Any]
) -> str:
    """Identify one unit of work.

    Scoped to the case as well as the bytes. Findings, proposals and the audit
    trail are all case-scoped, so the same sample arriving in a second case is
    genuinely new work -- suppressing it would leave that case with no analysis
    at all. Caching of *expensive derived output* across cases (a Ghidra
    decompilation of identical bytes) belongs in the artifacts table keyed by
    sha256, not in suppressing the job that would produce the findings.
    """
    canonical = json.dumps(params or {}, sort_keys=True, separators=(",", ":"))
    material = f"{case_id}|{sample_sha256 or '-'}|{kind.value}|{canonical}"
    return hashlib.sha256(material.encode()).hexdigest()


def enqueue_or_get(
    session: Session,
    *,
    case_id: str,
    kind: JobKind,
    sample_id: str | None = None,
    sample_sha256: str | None = None,
    params: dict[str, Any] | None = None,
) -> tuple[AnalysisJob, bool]:
    """Create a job, or return the existing one for identical work.

    Keyed on the sample's bytes rather than its row id, so resubmitting the same
    file under a different name does not queue the analysis twice.
    Returns (job, created).
    """
    params = params or {}
    key = idempotency_key(
        case_id=case_id, sample_sha256=sample_sha256, kind=kind, params=params
    )

    existing = session.scalar(select(AnalysisJob).where(AnalysisJob.idempotency_key == key))
    if existing is not None:
        return existing, False

    job = AnalysisJob(
        case_id=case_id,
        sample_id=sample_id,
        kind=kind,
        params=params,
        idempotency_key=key,
        state=JobState.QUEUED,
    )
    session.add(job)
    session.flush()
    return job, True


def get(session: Session, job_id: str) -> AnalysisJob | None:
    return session.get(AnalysisJob, job_id)


def for_case(session: Session, case_id: str, limit: int = 200) -> list[AnalysisJob]:
    stmt = (
        select(AnalysisJob)
        .where(AnalysisJob.case_id == case_id)
        .order_by(AnalysisJob.queued_at.desc())
        .limit(limit)
    )
    return list(session.scalars(stmt))


def mark_running(session: Session, job: AnalysisJob, worker: str | None = None) -> None:
    job.state = JobState.RUNNING
    job.started_at = datetime.now(timezone.utc)
    job.worker = worker
    session.flush()


def mark_finished(
    session: Session,
    job: AnalysisJob,
    *,
    state: JobState,
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    job.state = state
    job.finished_at = datetime.now(timezone.utc)
    job.result_summary = result or {}
    job.error = error
    session.flush()
