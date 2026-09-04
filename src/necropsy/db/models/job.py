from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Enum as SAEnum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from necropsy.db.base import Base, new_id, utcnow
from necropsy.enums import JobKind, JobState


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    sample_id: Mapped[str | None] = mapped_column(ForeignKey("samples.id"), default=None, index=True)

    kind: Mapped[JobKind] = mapped_column(SAEnum(JobKind, native_enum=False), index=True)
    state: Mapped[JobState] = mapped_column(
        SAEnum(JobState, native_enum=False), default=JobState.QUEUED, index=True
    )
    rq_job_id: Mapped[str | None] = mapped_column(String(64), default=None)
    params: Mapped[dict[str, Any]] = mapped_column("params_json", JSON, default=dict)

    # sha256(case_id + sample_sha256 + kind + canonical(params)). Unique, so
    # resubmitting the same file into the same case returns the existing job
    # instead of queueing the work twice. Case-scoped because findings are.
    idempotency_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    result_summary: Mapped[dict[str, Any]] = mapped_column("result_json", JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    worker: Mapped[str | None] = mapped_column(String(120), default=None)

    queued_at: Mapped[datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
