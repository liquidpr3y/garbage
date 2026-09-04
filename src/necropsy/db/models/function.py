from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from necropsy.db.base import Base, new_id, utcnow


class DecompiledFunction(Base):
    """One function recovered by Ghidra.

    Stored as rows rather than only inside the export artifact so the GUI can
    page and search them, and so Phase 5 has somewhere to hang a per-function
    AI summary without re-parsing a multi-megabyte JSON blob.
    """

    __tablename__ = "functions"
    __table_args__ = (UniqueConstraint("sample_id", "address", name="uq_function_address"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    sample_id: Mapped[str] = mapped_column(ForeignKey("samples.id"), index=True)
    job_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_jobs.id"), default=None, index=True
    )

    name: Mapped[str] = mapped_column(String(300), index=True)
    address: Mapped[str] = mapped_column(String(40), index=True)
    size: Mapped[int] = mapped_column(Integer, default=0)
    is_thunk: Mapped[bool] = mapped_column(Boolean, default=False)
    calling_convention: Mapped[str | None] = mapped_column(String(60), default=None)
    parameter_count: Mapped[int] = mapped_column(Integer, default=0)
    calls: Mapped[list[str]] = mapped_column("calls_json", JSON, default=list)

    decompiled: Mapped[str | None] = mapped_column(Text, default=None)
    decompile_error: Mapped[str | None] = mapped_column(Text, default=None)

    # sha256 of the normalised decompiled body. Identical bodies across samples
    # are shared code -- a cheaper and far more specific clustering signal than
    # a whole-file fuzzy hash, and it costs one hash per function.
    code_sha256: Mapped[str | None] = mapped_column(String(64), default=None, index=True)

    # Phase 5 fills these.
    ai_summary: Mapped[str | None] = mapped_column(Text, default=None)
    ai_summarised_at: Mapped[datetime | None] = mapped_column(default=None)

    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    def to_summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "address": self.address,
            "size": self.size,
            "is_thunk": self.is_thunk,
            "parameter_count": self.parameter_count,
            "calls": self.calls,
            "has_decompilation": self.decompiled is not None,
            "has_ai_summary": self.ai_summary is not None,
        }
