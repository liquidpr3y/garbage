from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from necropsy.contracts.events import Event, EventType, case_channel
from necropsy.contracts.host import HostServices
from necropsy.db.models import AuditAction, Case
from necropsy.db.repos import actions, audit, cases, findings, jobs
from necropsy.enums import ActionState, CaseStatus, Severity


def create_case(
    session: Session,
    host: HostServices,
    *,
    name: str,
    severity: Severity = Severity.INFO,
    tags: list[str] | None = None,
    host_engagement_ref: str | None = None,
    ai_disclosure_allowed: bool = False,
    actor: str | None = None,
) -> Case:
    actor = actor or host.actor()
    case = cases.create(
        session,
        name=name,
        severity=severity,
        tags=tags or [],
        host_engagement_ref=host_engagement_ref,
        ai_disclosure_allowed=ai_disclosure_allowed,
    )
    audit.record(
        session,
        action=AuditAction.CASE_CREATED,
        actor=actor,
        case_id=case.id,
        object_type="case",
        object_id=case.id,
        detail={"name": name, "ai_disclosure_allowed": ai_disclosure_allowed},
    )
    host.publish(
        case_channel(case.id),
        Event(type=EventType.CASE_CREATED, case_id=case.id, payload={"name": name}),
    )
    return case


def update_case(
    session: Session,
    host: HostServices,
    case: Case,
    *,
    actor: str | None = None,
    **changes: Any,
) -> Case:
    actor = actor or host.actor()
    applied: dict[str, Any] = {}
    for field in ("name", "status", "severity", "summary", "tags", "ai_disclosure_allowed",
                  "host_engagement_ref"):
        if field in changes and changes[field] is not None:
            setattr(case, field, changes[field])
            value = changes[field]
            applied[field] = value.value if hasattr(value, "value") else value
    session.flush()

    action = (
        AuditAction.CASE_CLOSED
        if applied.get("status") == CaseStatus.CLOSED.value
        else AuditAction.CASE_UPDATED
    )
    audit.record(
        session,
        action=action,
        actor=actor,
        case_id=case.id,
        object_type="case",
        object_id=case.id,
        detail=applied,
    )
    host.publish(
        case_channel(case.id),
        Event(type=EventType.CASE_UPDATED, case_id=case.id, payload=applied),
    )
    return case


def timeline(session: Session, case_id: str, limit: int = 400) -> list[dict[str, Any]]:
    """Everything that has happened to a case, newest first.

    Merged rather than tabbed: the operator's question is "what happened to this
    case", not "show me the jobs table". Audit rows are included because the
    human decisions are the part worth reading back.
    """
    entries: list[dict[str, Any]] = []

    for job in jobs.for_case(session, case_id):
        entries.append(
            {
                "at": job.queued_at,
                "kind": "job",
                "id": job.id,
                "title": f"{job.kind.value} ({job.state.value})",
                "state": job.state.value,
                "job_kind": job.kind.value,
                "error": job.error,
            }
        )

    for finding in findings.for_case(session, case_id):
        entries.append(
            {
                "at": finding.created_at,
                "kind": "finding",
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "producer": finding.producer.value,
                "attack_technique_ids": finding.attack_technique_ids,
                "kill_chain_phase": (
                    finding.kill_chain_phase.value if finding.kill_chain_phase else None
                ),
            }
        )

    for action in actions.for_case(session, case_id, state=None):
        entries.append(
            {
                "at": action.created_at,
                "kind": "action",
                "id": action.id,
                "title": action.title,
                "state": action.state.value,
                "risk_score": action.risk_score,
                "risk_band": action.risk_band,
                "available": action.available,
                "decided_by": action.decided_by,
            }
        )

    for event in audit.for_case(session, case_id):
        entries.append(
            {
                "at": event.at,
                "kind": "audit",
                "id": event.id,
                "title": event.action,
                "actor": event.actor,
                "detail": event.detail,
            }
        )

    entries.sort(key=lambda e: e["at"], reverse=True)
    return entries[:limit]


def open_action_count(session: Session, case_id: str) -> int:
    return len(actions.for_case(session, case_id, state=ActionState.PROPOSED))
