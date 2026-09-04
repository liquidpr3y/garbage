from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Enum as SAEnum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from necropsy.db.base import Base, new_id, utcnow
from necropsy.enums import ArtifactKind


class Artifact(Base):
    """Anything *derived* from a sample: unpacked blobs, PCAPs, memdumps,
    Ghidra projects, screenshots.

    Same vault, same handling rules as a sample -- a dumped payload is still a
    payload. No producers in Phase 1; Phases 2 and 3 fill this.
    """

    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    sample_id: Mapped[str | None] = mapped_column(ForeignKey("samples.id"), default=None, index=True)
    job_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_jobs.id"), default=None, index=True
    )
    kind: Mapped[ArtifactKind] = mapped_column(
        SAEnum(ArtifactKind, native_enum=False), default=ArtifactKind.OTHER
    )
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    vault_uri: Mapped[str | None] = mapped_column(String(500), default=None)
    size: Mapped[int] = mapped_column(Integer, default=0)
    meta: Mapped[dict[str, Any]] = mapped_column("meta_json", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
