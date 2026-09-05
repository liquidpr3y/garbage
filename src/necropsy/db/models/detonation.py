from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from necropsy.db.base import Base, new_id, utcnow


class Detonation(Base):
    """One observed run of one sample on one target.

    The fingerprint columns are not bookkeeping. Six months later "the sample
    did nothing" is only interpretable if you know what it ran on, whether the
    architecture matched, and whether the network was live -- so target, arch,
    snapshot, egress and fidelity are stored on the run itself rather than
    inferred from whatever the config happens to say at read time.
    """

    __tablename__ = "detonations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    sample_id: Mapped[str] = mapped_column(ForeignKey("samples.id"), index=True)
    job_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_jobs.id"), default=None, index=True
    )

    target: Mapped[str] = mapped_column(String(60))
    target_arch: Mapped[str] = mapped_column(String(20))
    target_os: Mapped[str] = mapped_column(String(20))
    snapshot: Mapped[str] = mapped_column(String(200), default="")
    egress: Mapped[bool] = mapped_column(Boolean, default=False)
    fidelity: Mapped[str] = mapped_column(String(20), default="unknown")
    fingerprint: Mapped[dict[str, Any]] = mapped_column("fingerprint_json", JSON, default=dict)

    guest_path: Mapped[str | None] = mapped_column(String(500), default=None)
    guest_hostname: Mapped[str | None] = mapped_column(String(200), default=None)
    exec_detail: Mapped[str | None] = mapped_column(Text, default=None)

    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    run_seconds: Mapped[int] = mapped_column(Integer, default=0)

    telemetry_events: Mapped[int] = mapped_column(Integer, default=0)
    telemetry_source: Mapped[str | None] = mapped_column(String(120), default=None)
    telemetry_note: Mapped[str | None] = mapped_column(Text, default=None)
    network_summary: Mapped[dict[str, Any]] = mapped_column("network_json", JSON, default=dict)
    behaviour_summary: Mapped[dict[str, Any]] = mapped_column("behaviour_json", JSON, default=dict)

    # False means the run supports no conclusion -- see behaviour._verdict.
    readable: Mapped[bool] = mapped_column(Boolean, default=True)
    verdict_note: Mapped[str | None] = mapped_column(Text, default=None)

    state: Mapped[str] = mapped_column(String(20), default="running", index=True)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    reverted: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(default=utcnow)
