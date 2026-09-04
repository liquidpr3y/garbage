from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from necropsy.db.base import Base, new_id, utcnow
from necropsy.enums import Arch, FileType, SampleSource, StorageState


class Sample(Base):
    """A sample is global and content-addressed; it is not owned by a case.

    The same file observed in two cases is one vault object and one hash record
    with two observation contexts (see CaseSample). Collapsing the two means
    re-storing samples and losing the cross-case pivot, which is the entire
    point of fuzzy-hash clustering in Phase 2.
    """

    __tablename__ = "samples"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)

    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    sha1: Mapped[str] = mapped_column(String(40), index=True)
    md5: Mapped[str] = mapped_column(String(32), index=True)
    tlsh: Mapped[str | None] = mapped_column(String(72), default=None, index=True)
    ssdeep: Mapped[str | None] = mapped_column(String(200), default=None)

    size: Mapped[int] = mapped_column(Integer)
    mime: Mapped[str | None] = mapped_column(String(120), default=None)
    magic: Mapped[str | None] = mapped_column(Text, default=None)
    file_type: Mapped[FileType] = mapped_column(
        SAEnum(FileType, native_enum=False), default=FileType.UNKNOWN, index=True
    )
    arch: Mapped[Arch] = mapped_column(
        SAEnum(Arch, native_enum=False), default=Arch.UNKNOWN, index=True
    )
    entropy: Mapped[float | None] = mapped_column(Float, default=None)

    storage_state: Mapped[StorageState] = mapped_column(
        SAEnum(StorageState, native_enum=False), default=StorageState.VAULTED
    )
    vault_uri: Mapped[str | None] = mapped_column(String(500), default=None)

    # Producer-specific identification detail (PE characteristics, signature
    # presence, section entropies). Schema-free on purpose -- Phase 2 adds keys.
    identity: Mapped[dict[str, Any]] = mapped_column("identity_json", JSON, default=dict)

    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)

    case_samples: Mapped[list[CaseSample]] = relationship("CaseSample", back_populates="sample")


class CaseSample(Base):
    """Per-case observation context for a sample."""

    __tablename__ = "case_samples"
    __table_args__ = (UniqueConstraint("case_id", "sample_id", name="uq_case_sample"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    sample_id: Mapped[str] = mapped_column(ForeignKey("samples.id"), index=True)

    observed_filename: Mapped[str | None] = mapped_column(String(500), default=None)
    source: Mapped[SampleSource] = mapped_column(
        SAEnum(SampleSource, native_enum=False), default=SampleSource.UPLOAD
    )
    submitted_by: Mapped[str] = mapped_column(String(120), default="local")
    note: Mapped[str | None] = mapped_column(Text, default=None)
    added_at: Mapped[datetime] = mapped_column(default=utcnow)

    case: Mapped[Any] = relationship("Case", back_populates="case_samples")
    sample: Mapped[Sample] = relationship("Sample", back_populates="case_samples")
