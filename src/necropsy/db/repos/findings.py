from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from necropsy.db.models import Finding
from necropsy.enums import KillChainPhase, Producer, Severity


def upsert(
    session: Session,
    *,
    case_id: str,
    producer: Producer,
    type: str,
    title: str,
    dedupe_key: str,
    sample_id: str | None = None,
    job_id: str | None = None,
    description: str | None = None,
    severity: Severity = Severity.INFO,
    confidence: float = 0.5,
    attack_technique_ids: list[str] | None = None,
    kill_chain_phase: KillChainPhase | None = None,
    evidence: dict[str, Any] | None = None,
) -> tuple[Finding, bool]:
    """Create a finding, or refresh the existing one with the same dedupe key.

    Re-running a job must not multiply findings; it should update them.
    Returns (finding, created).
    """
    existing = session.scalar(
        select(Finding).where(Finding.case_id == case_id, Finding.dedupe_key == dedupe_key)
    )
    if existing is not None:
        existing.title = title
        existing.description = description
        existing.severity = severity
        existing.confidence = confidence
        existing.evidence = evidence or {}
        existing.job_id = job_id or existing.job_id
        if attack_technique_ids:
            existing.attack_technique_ids = attack_technique_ids
        if kill_chain_phase:
            existing.kill_chain_phase = kill_chain_phase
        # The mirror is now stale; the Phase 4 reindex picks this up.
        existing.mirrored_at = None
        session.flush()
        return existing, False

    finding = Finding(
        case_id=case_id,
        sample_id=sample_id,
        job_id=job_id,
        producer=producer,
        type=type,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        attack_technique_ids=attack_technique_ids or [],
        kill_chain_phase=kill_chain_phase,
        evidence=evidence or {},
        dedupe_key=dedupe_key,
    )
    session.add(finding)
    session.flush()
    return finding, True


def for_case(session: Session, case_id: str, limit: int = 500) -> list[Finding]:
    stmt = (
        select(Finding)
        .where(Finding.case_id == case_id)
        .order_by(Finding.created_at.desc())
        .limit(limit)
    )
    return list(session.scalars(stmt))


def unmirrored(session: Session, limit: int = 1000) -> list[Finding]:
    """Findings the Elastic sink has not confirmed. Input to `necropsy reindex`."""
    stmt = select(Finding).where(Finding.mirrored_at.is_(None)).limit(limit)
    return list(session.scalars(stmt))
