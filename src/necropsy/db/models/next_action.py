from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Enum as SAEnum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from necropsy.db.base import Base, new_id, utcnow
from necropsy.enums import ActionState


class NextAction(Base):
    """A risk-scored next step awaiting a human decision.

    This is the connective tissue with the pentest module: a stage completes,
    results push into the next stage, and the operator chooses what happens
    next with blast radius visible before the click. It is a Phase 1 table
    precisely so Phases 2-5 become new producers of rows rather than new
    pipelines.

    ``decided_by`` / ``decided_at`` are also the chain of custody for anything
    consequential -- notably that a human, named, authorised each detonation.
    """

    __tablename__ = "next_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    sample_id: Mapped[str | None] = mapped_column(ForeignKey("samples.id"), default=None)
    origin_job_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_jobs.id"), default=None, index=True
    )

    kind: Mapped[str] = mapped_column(String(60), index=True)
    title: Mapped[str] = mapped_column(String(300))
    rationale: Mapped[str] = mapped_column(Text)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_band: Mapped[str] = mapped_column(String(20), default="minimal")
    risk_factors: Mapped[list[dict[str, Any]]] = mapped_column("risk_json", JSON, default=list)
    estimated_cost_s: Mapped[int | None] = mapped_column(Integer, default=None)

    params: Mapped[dict[str, Any]] = mapped_column("params_json", JSON, default=dict)

    # False for kinds a later phase implements. The GUI greys them out rather
    # than hiding them, so the operator sees the whole decision space.
    available: Mapped[bool] = mapped_column(default=True)
    unavailable_reason: Mapped[str | None] = mapped_column(String(300), default=None)

    state: Mapped[ActionState] = mapped_column(
        SAEnum(ActionState, native_enum=False), default=ActionState.PROPOSED, index=True
    )
    decided_by: Mapped[str | None] = mapped_column(String(120), default=None)
    decided_at: Mapped[datetime | None] = mapped_column(default=None)
    decision_note: Mapped[str | None] = mapped_column(Text, default=None)
    resulting_job_id: Mapped[str | None] = mapped_column(String(36), default=None)

    created_at: Mapped[datetime] = mapped_column(default=utcnow)
