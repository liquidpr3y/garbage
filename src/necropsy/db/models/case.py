from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Enum as SAEnum, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from necropsy.db.base import Base, new_id, utcnow
from necropsy.enums import CaseStatus, Severity


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[CaseStatus] = mapped_column(
        SAEnum(CaseStatus, native_enum=False), default=CaseStatus.OPEN, index=True
    )
    severity: Mapped[Severity] = mapped_column(
        SAEnum(Severity, native_enum=False), default=Severity.INFO
    )
    summary: Mapped[str | None] = mapped_column(Text, default=None)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Link out to a pentest-module engagement without either side owning the
    # other's schema. Nullable because the host may not have engagements yet.
    host_engagement_ref: Mapped[str | None] = mapped_column(String(200), default=None, index=True)

    # Phase 5 gate. Defaults to false: some samples come from client engagements
    # where sending decompiled code to a third-party API is a contractual
    # problem. Cheap now, awkward to retrofit once the AI layer exists.
    ai_disclosure_allowed: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    case_samples: Mapped[list[Any]] = relationship(
        "CaseSample", back_populates="case", cascade="all, delete-orphan"
    )
