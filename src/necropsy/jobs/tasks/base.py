"""Job execution wrapper: state transitions, events, error handling."""

from __future__ import annotations

import logging
import socket
import traceback
from typing import Any

from sqlalchemy.orm import Session

from necropsy.contracts.events import Event, EventType, case_channel
from necropsy.contracts.host import HostServices
from necropsy.db.models import AnalysisJob, AuditAction, Finding
from necropsy.db.repos import audit, findings as findings_repo, jobs as jobs_repo
from necropsy.db.session import session_scope
from necropsy.enums import JobState, KillChainPhase, Producer, Severity
from necropsy.jobs.registry import handler_for
from necropsy.runtime import get_host
from necropsy.sinks import get_sink

log = logging.getLogger(__name__)


def execute_job(job_id: str) -> None:
    """Entry point for both the RQ worker and the inline runner."""
    host = get_host()
    with session_scope() as session:
        job = jobs_repo.get(session, job_id)
        if job is None:
            log.error("job %s vanished before execution", job_id)
            return
        if job.state not in (JobState.QUEUED, JobState.RUNNING):
            log.info("job %s already in state %s, skipping", job_id, job.state)
            return

        kind = job.kind
        jobs_repo.mark_running(session, job, worker=socket.gethostname())
        _publish(host, job, EventType.JOB_STARTED, {"kind": kind.value})

    try:
        handler = handler_for(kind)
        with session_scope() as session:
            job = jobs_repo.get(session, job_id)
            if job is None:
                raise RuntimeError(f"job {job_id} vanished mid-execution")
            result = handler(session, host, job)
            jobs_repo.mark_finished(session, job, state=JobState.SUCCEEDED, result=result or {})
            _mark_originating_action_executed(session, job)
            audit.record(
                session,
                action=AuditAction.JOB_FINISHED,
                actor=host.actor(),
                case_id=job.case_id,
                object_type="job",
                object_id=job.id,
                detail={"kind": job.kind.value, "state": "succeeded"},
            )
            _publish(host, job, EventType.JOB_SUCCEEDED, {"kind": job.kind.value, **(result or {})})
    except Exception as exc:  # noqa: BLE001 - a failed job must not kill the worker
        log.exception("job %s failed", job_id)
        with session_scope() as session:
            job = jobs_repo.get(session, job_id)
            if job is not None:
                jobs_repo.mark_finished(
                    session,
                    job,
                    state=JobState.FAILED,
                    error=f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=6)}",
                )
                _publish(
                    host,
                    job,
                    EventType.JOB_FAILED,
                    {"kind": job.kind.value, "error": f"{type(exc).__name__}: {exc}"},
                )


def _mark_originating_action_executed(session: Session, job: AnalysisJob) -> None:
    """Close the loop: an accepted proposal becomes executed once its job lands."""
    from sqlalchemy import select

    from necropsy.db.models import NextAction
    from necropsy.enums import ActionState

    rows = session.scalars(
        select(NextAction).where(
            NextAction.resulting_job_id == job.id,
            NextAction.state == ActionState.ACCEPTED,
        )
    )
    for action in rows:
        action.state = ActionState.EXECUTED
    session.flush()


def _publish(host: HostServices, job: AnalysisJob, event_type: EventType, payload: dict) -> None:
    host.publish(
        case_channel(job.case_id),
        Event(
            type=event_type,
            case_id=job.case_id,
            payload={"job_id": job.id, **payload},
        ),
    )


def emit_finding(
    session: Session,
    host: HostServices,
    job: AnalysisJob,
    *,
    producer: Producer,
    type: str,
    title: str,
    dedupe_key: str,
    description: str | None = None,
    severity: Severity = Severity.INFO,
    confidence: float = 0.5,
    attack_technique_ids: list[str] | None = None,
    kill_chain_phase: KillChainPhase | None = None,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    """Create or refresh a finding, mirror it, and tell the case's subscribers."""
    finding, created = findings_repo.upsert(
        session,
        case_id=job.case_id,
        sample_id=job.sample_id,
        job_id=job.id,
        producer=producer,
        type=type,
        title=title,
        dedupe_key=dedupe_key,
        description=description,
        severity=severity,
        confidence=confidence,
        attack_technique_ids=attack_technique_ids,
        kill_chain_phase=kill_chain_phase,
        evidence=evidence,
    )

    # Best-effort mirror. A sink failure must never lose the finding: mirrored_at
    # stays null and `necropsy reindex` picks it up later.
    try:
        doc_id = get_sink().emit(finding)
        if doc_id:
            from necropsy.db.base import utcnow

            finding.elastic_doc_id = doc_id
            finding.mirrored_at = utcnow()
    except Exception as exc:  # noqa: BLE001
        log.warning("finding sink failed for %s: %s", finding.id, exc)

    if created:
        _publish(
            host,
            job,
            EventType.FINDING_CREATED,
            {
                "finding_id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "type": finding.type,
            },
        )
    return finding
