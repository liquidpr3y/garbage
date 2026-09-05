"""AI outputs: case reports, drafted detection rules, and what the layer can do.

Everything here is model-generated and labelled as such. The endpoints exist so
the GUI can show it *next to* the derived findings, not instead of them.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from necropsy.analysis import artifacts as artifact_store
from necropsy.api.deps import db_session, host_services
from necropsy.config import get_settings
from necropsy.contracts.host import HostServices
from necropsy.db.models import Artifact
from necropsy.db.repos import cases as cases_repo, samples as samples_repo
from necropsy.enums import ArtifactKind
from necropsy.schemas.ai import AIStatus

router = APIRouter(tags=["ai"])


@router.get("/ai/status", response_model=AIStatus)
def ai_status() -> Any:
    """Whether this install can call the API, and what it would cost against."""
    from necropsy.ai.client import DEFAULT_MODEL, credential_source, have_sdk

    settings = get_settings()
    source = credential_source()
    return AIStatus(
        sdk_installed=have_sdk(),
        credentials=source is not None,
        credential_source=source,
        model=settings.ai_model or DEFAULT_MODEL,
        effort=settings.ai_effort,
        max_functions=settings.ai_max_functions,
        goodware_dir=settings.ai_goodware_dir,
        goodware_configured=bool(settings.ai_goodware_dir),
    )


@router.get("/cases/{case_id}/report")
def case_report(
    case_id: str,
    session: Session = Depends(db_session),
    host: HostServices = Depends(host_services),
) -> dict[str, Any]:
    case = cases_repo.get(session, case_id)
    if case is None:
        raise HTTPException(404, "case not found")

    for link in samples_repo.for_case(session, case_id):
        artifact = artifact_store.latest(session, link.sample.id, ArtifactKind.REPORT)
        if artifact is None:
            continue
        payload = artifact_store.load_json(
            session, artifact, actor=host.actor(), case_id=case_id
        )
        session.commit()
        return {
            "case_id": case_id,
            "generated_by": artifact.meta.get("model"),
            "generated_at": artifact.created_at.isoformat(),
            "ai_generated": True,
            "report": payload,
        }

    raise HTTPException(404, "no AI report for this case; run an ai_report job first")


@router.get("/cases/{case_id}/yara")
def case_yara_rules(
    case_id: str,
    session: Session = Depends(db_session),
    host: HostServices = Depends(host_services),
) -> dict[str, Any]:
    """Drafted rules that passed validation. Failed drafts are never stored."""
    if cases_repo.get(session, case_id) is None:
        raise HTTPException(404, "case not found")

    sample_ids = [link.sample.id for link in samples_repo.for_case(session, case_id)]
    if not sample_ids:
        return {"case_id": case_id, "rules": []}

    rows = list(
        session.scalars(
            select(Artifact)
            .where(
                Artifact.sample_id.in_(sample_ids),
                Artifact.kind == ArtifactKind.YARA_RULE,
            )
            .order_by(Artifact.created_at.desc())
        )
    )

    vault = None
    rules = []
    for artifact in rows:
        if vault is None:
            from necropsy.intake.service import open_vault

            vault = open_vault(session, actor=host.actor(), case_id=case_id)
        rules.append(
            {
                "rule_name": artifact.meta.get("rule_name"),
                "validated": artifact.meta.get("validated", False),
                "attempts": artifact.meta.get("attempts"),
                "corpus_size": artifact.meta.get("corpus_size"),
                "tested_against_real_goodware": artifact.meta.get("real_goodware", False),
                "model": artifact.meta.get("model"),
                "created_at": artifact.created_at.isoformat(),
                "rule_text": vault.read_bytes(
                    artifact.sha256, actor=host.actor(), reason="yara_export"
                ).decode(),
            }
        )
    session.commit()
    return {"case_id": case_id, "rules": rules}
