"""Re-run Sigma rules against a detonation that already happened.

Separate from the detonation itself because rule sets change far more often
than runs do. After writing or importing rules you want to sweep existing cases
without re-detonating anything -- which is both slow and, on a shared lab, not
free.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from necropsy.attack import sigma
from necropsy.config import get_settings
from necropsy.contracts.host import HostServices
from necropsy.db.models import AnalysisJob, Detonation
from necropsy.elastic.client import ElasticClient
from necropsy.elastic.sysmon import TelemetryWindow
from necropsy.enums import KillChainPhase, Producer, Severity
from necropsy.jobs.tasks.base import emit_finding


class NoTelemetryToSweep(RuntimeError):
    pass


def latest_detonation(session: Session, case_id: str, sample_id: str | None) -> Detonation | None:
    stmt = select(Detonation).where(Detonation.case_id == case_id)
    if sample_id:
        stmt = stmt.where(Detonation.sample_id == sample_id)
    return session.scalars(stmt.order_by(Detonation.started_at.desc())).first()


def run(session: Session, host: HostServices, job: AnalysisJob) -> dict[str, Any]:
    settings = get_settings()
    detonation = latest_detonation(session, job.case_id, job.sample_id)
    if detonation is None:
        raise NoTelemetryToSweep(
            "no detonation on this case to sweep; run a dynamic analysis first"
        )

    client = ElasticClient.try_from_settings()
    if client is None:
        raise NoTelemetryToSweep(
            "NECROPSY_ELASTIC_URL is not set; there is no telemetry to sweep"
        )

    window = TelemetryWindow(
        start=detonation.started_at - timedelta(seconds=30),
        end=(detonation.finished_at or detonation.started_at)
        + timedelta(seconds=settings.elastic_settle_seconds + 30),
        host=detonation.guest_hostname,
    )
    result = sigma.run(
        client, settings.elastic_sysmon_index, window,
        events_in_window=detonation.telemetry_events,
    )
    emit_sigma_findings(session, host, job, result, detonation)
    return {**result.summary(), "detonation_id": detonation.id}


def emit_sigma_findings(
    session: Session,
    host: HostServices,
    job: AnalysisJob,
    result: sigma.SigmaRunResult,
    detonation: Detonation | None,
) -> int:
    """Turn rule hits into findings, and say so when the sweep proved nothing."""
    from necropsy.attack.catalogue import get_catalogue

    catalogue = get_catalogue()

    for hit in result.hits:
        rule = hit.rule
        phase = None
        for technique in rule.attack_techniques:
            phase = catalogue.kill_chain_for_technique(technique)
            if phase:
                break
        emit_finding(
            session, host, job,
            producer=Producer.SYSMON,
            type=f"sigma:{rule.id}",
            title=f"Sigma: {rule.title}",
            dedupe_key=f"sigma:{rule.id}",
            description=(
                rule.description
                + f"\n\nMatched {hit.count} event(s). Rule status: {rule.status}."
            ).strip(),
            severity=rule.severity,
            confidence=rule.confidence,
            attack_technique_ids=rule.attack_techniques,
            kill_chain_phase=phase or KillChainPhase.EXPLOITATION,
            evidence={
                "rule_id": rule.id,
                "rule_source": rule.source,
                "match_count": hit.count,
                "query": rule.query,
                "samples": hit.samples[:3],
                "detonation_id": detonation.id if detonation else None,
                "fidelity": detonation.fidelity if detonation else None,
            },
        )

    if result.inconclusive and result.note:
        emit_finding(
            session, host, job,
            producer=Producer.SYSMON,
            type="sigma_sweep_inconclusive",
            title="Sigma sweep produced no readable result",
            dedupe_key="sigma_sweep_inconclusive",
            description=result.note
            + (f"\n\n{result.field_adaptation}" if result.field_adaptation else ""),
            severity=Severity.INFO, confidence=1.0,
            evidence=result.summary(),
        )
    return len(result.hits)
