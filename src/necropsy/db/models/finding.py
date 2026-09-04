from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Enum as SAEnum,
    Float,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from necropsy.db.base import Base, new_id, utcnow
from necropsy.enums import KillChainPhase, Producer, Severity


class Finding(Base):
    """One normalised finding type, many producers.

    A YARA hit, a PE anomaly, a Sysmon process tree, a Zeek DNS anomaly and a
    Claude-authored inference all land here. That is what makes Phase 4's
    technique heatmap a GROUP BY rather than a second pipeline.

    The ATT&CK and kill chain columns exist from Phase 1 and stay null until
    Phase 4 populates them. Adding them after three phases of findings have
    accumulated is the expensive version of this decision.
    """

    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("case_id", "dedupe_key", name="uq_finding_dedupe"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    sample_id: Mapped[str | None] = mapped_column(ForeignKey("samples.id"), default=None, index=True)
    job_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_jobs.id"), default=None, index=True
    )

    producer: Mapped[Producer] = mapped_column(SAEnum(Producer, native_enum=False), index=True)
    type: Mapped[str] = mapped_column(String(80), index=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str | None] = mapped_column(Text, default=None)

    # Severity and confidence are deliberately separate. A high-severity,
    # low-confidence AI inference must not read like a YARA hit.
    severity: Mapped[Severity] = mapped_column(
        SAEnum(Severity, native_enum=False), default=Severity.INFO, index=True
    )
    confidence: Mapped[float] = mapped_column(Float, default=0.5)

    attack_technique_ids: Mapped[list[str]] = mapped_column("attack_json", JSON, default=list)
    kill_chain_phase: Mapped[KillChainPhase | None] = mapped_column(
        SAEnum(KillChainPhase, native_enum=False), default=None, index=True
    )

    evidence: Mapped[dict[str, Any]] = mapped_column("evidence_json", JSON, default=dict)
    dedupe_key: Mapped[str] = mapped_column(String(200))

    # Bidirectional Elastic: findings mirror into a necropsy-findings-* ECS data
    # stream so they are pivotable in Kibana beside raw lab telemetry. SQLite
    # stays the system of record and the mirror is best-effort and replayable --
    # a SIEM outage must never fail an ingest or lose a finding. Populated by
    # the Phase 4 sink; `necropsy reindex` backfills anything null.
    elastic_doc_id: Mapped[str | None] = mapped_column(String(120), default=None)
    mirrored_at: Mapped[datetime | None] = mapped_column(default=None)

    created_at: Mapped[datetime] = mapped_column(default=utcnow)
