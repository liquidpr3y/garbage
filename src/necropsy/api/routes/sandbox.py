"""Sandbox views -- what the GUI's detonation timeline binds to."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from necropsy.analysis import artifacts as artifact_store
from necropsy.api.deps import db_session, host_services
from necropsy.config import get_settings
from necropsy.contracts.host import HostServices
from necropsy.db.models import Detonation
from necropsy.db.repos import cases as cases_repo
from necropsy.enums import ArtifactKind
from necropsy.schemas.sandbox import DetonationOut, SandboxStatus

router = APIRouter(tags=["sandbox"])


@router.get("/sandbox/status", response_model=SandboxStatus)
def sandbox_status() -> Any:
    """Whether this install can detonate, and if not, exactly what is missing."""
    from necropsy.elastic.client import ElasticClient
    from necropsy.sandbox.targets import REGISTRY, NoTargetConfigured, build_target

    settings = get_settings()
    ready, reason, caps = True, None, None
    try:
        target = build_target()
        caps = {
            "name": target.caps.name,
            "arch": target.caps.arch.value,
            "os": target.caps.os,
            "snapshot": target.caps.snapshot,
            "supports_egress": target.caps.supports_egress,
            "guest_hostname": target.guest_hostname,
        }
    except NoTargetConfigured as exc:
        ready, reason = False, str(exc)
    except Exception as exc:  # noqa: BLE001
        ready, reason = False, f"{type(exc).__name__}: {exc}"

    elastic = ElasticClient.try_from_settings()
    elastic_ready = False
    elastic_note = "NECROPSY_ELASTIC_URL is not set; no host telemetry will be collected"
    if elastic is not None:
        try:
            version = elastic.ping().get("version", {}).get("number", "?")
            elastic_ready, elastic_note = True, f"Elasticsearch {version}"
        except Exception as exc:  # noqa: BLE001
            elastic_note = f"unreachable: {exc}"

    return SandboxStatus(
        enabled=settings.sandbox_enabled,
        ready=ready,
        reason=reason,
        target=settings.sandbox_target,
        known_targets=sorted(REGISTRY),
        capabilities=caps,
        pcap_interface=settings.sandbox_pcap_interface,
        elastic_ready=elastic_ready,
        elastic_note=elastic_note,
        run_seconds=settings.sandbox_run_seconds,
    )


@router.get("/cases/{case_id}/detonations", response_model=list[DetonationOut])
def list_detonations(case_id: str, session: Session = Depends(db_session)) -> Any:
    if cases_repo.get(session, case_id) is None:
        raise HTTPException(404, "case not found")
    return list(
        session.scalars(
            select(Detonation)
            .where(Detonation.case_id == case_id)
            .order_by(Detonation.started_at.desc())
        )
    )


@router.get("/detonations/{detonation_id}", response_model=DetonationOut)
def get_detonation(detonation_id: str, session: Session = Depends(db_session)) -> Any:
    row = session.get(Detonation, detonation_id)
    if row is None:
        raise HTTPException(404, "detonation not found")
    return row


@router.get("/detonations/{detonation_id}/timeline")
def detonation_timeline(
    detonation_id: str,
    limit: int = 2000,
    session: Session = Depends(db_session),
    host: HostServices = Depends(host_services),
) -> dict[str, Any]:
    """The raw Sysmon events behind a run, for the sandbox timeline view."""
    row = session.get(Detonation, detonation_id)
    if row is None:
        raise HTTPException(404, "detonation not found")

    artifact = artifact_store.latest(session, row.sample_id, ArtifactKind.TELEMETRY)
    events: list[dict[str, Any]] = []
    if artifact is not None:
        payload = artifact_store.load_json(
            session, artifact, actor=host.actor(), case_id=row.case_id
        )
        session.commit()
        events = payload.get("events", [])[:limit]

    return {
        "detonation_id": row.id,
        "readable": row.readable,
        "verdict_note": row.verdict_note,
        "telemetry_note": row.telemetry_note,
        "fidelity": row.fidelity,
        "event_count": row.telemetry_events,
        "events": events,
        "network": row.network_summary,
        "behaviours": row.behaviour_summary,
    }
