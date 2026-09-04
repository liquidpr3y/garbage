from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from necropsy.db.base import Base, new_id, utcnow


class AuditEvent(Base):
    """Append-only. The repository layer exposes no update or delete path.

    This is chain of custody: who ingested which bytes, who read them back out
    of the vault, who authorised a detonation. Treat it as evidentiary from day
    one, because retrofitting it means the early cases never have it.
    """

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str | None] = mapped_column(String(36), default=None, index=True)
    actor: Mapped[str] = mapped_column(String(120), default="local", index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    object_type: Mapped[str | None] = mapped_column(String(60), default=None)
    object_id: Mapped[str | None] = mapped_column(String(120), default=None, index=True)
    detail: Mapped[dict[str, Any]] = mapped_column("detail_json", JSON, default=dict)
    note: Mapped[str | None] = mapped_column(Text, default=None)
    at: Mapped[datetime] = mapped_column(default=utcnow, index=True)


class AuditAction:
    """Action names used across the codebase, kept in one place."""

    CASE_CREATED = "case.created"
    CASE_UPDATED = "case.updated"
    CASE_CLOSED = "case.closed"
    SAMPLE_INGESTED = "sample.ingested"
    SAMPLE_ATTACHED = "sample.attached"
    SAMPLE_DEDUPED = "sample.deduped"
    VAULT_WRITE = "vault.write"
    VAULT_READ = "vault.read"
    JOB_ENQUEUED = "job.enqueued"
    JOB_FINISHED = "job.finished"
    ACTION_PROPOSED = "action.proposed"
    ACTION_ACCEPTED = "action.accepted"
    ACTION_REJECTED = "action.rejected"
    EXPORT = "export"
