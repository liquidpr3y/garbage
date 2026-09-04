"""Append-only audit log. There is deliberately no update or delete here."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from necropsy.db.models import AuditEvent


def record(
    session: Session,
    *,
    action: str,
    actor: str = "local",
    case_id: str | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    detail: dict[str, Any] | None = None,
    note: str | None = None,
) -> AuditEvent:
    event = AuditEvent(
        action=action,
        actor=actor,
        case_id=case_id,
        object_type=object_type,
        object_id=object_id,
        detail=detail or {},
        note=note,
    )
    session.add(event)
    session.flush()
    return event


def for_case(session: Session, case_id: str, limit: int = 500) -> list[AuditEvent]:
    stmt = (
        select(AuditEvent)
        .where(AuditEvent.case_id == case_id)
        .order_by(AuditEvent.at.desc())
        .limit(limit)
    )
    return list(session.scalars(stmt))
