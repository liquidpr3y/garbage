"""Derived-artifact storage.

Anything an analysis job produces that is too big for a finding's evidence
blob -- a strings dump, a Ghidra export, later a PCAP -- goes into the vault
under its own content address and gets an `artifacts` row pointing at it.

Same vault, same encryption, same 0o400, same audit trail as a sample. That is
deliberate: an unpacked payload dumped by a future Phase 2 unpacker is not
safer than the file it came out of.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from necropsy.db.models import Artifact
from necropsy.enums import ArtifactKind
from necropsy.intake.service import open_vault


def store_json(
    session: Session,
    *,
    payload: Any,
    kind: ArtifactKind,
    sample_id: str,
    job_id: str | None,
    case_id: str,
    actor: str,
    meta: dict[str, Any] | None = None,
) -> Artifact:
    data = json.dumps(payload, indent=None, separators=(",", ":")).encode()
    return store_bytes(
        session, data=data, kind=kind, sample_id=sample_id, job_id=job_id,
        case_id=case_id, actor=actor, meta={**(meta or {}), "content_type": "application/json"},
    )


def store_bytes(
    session: Session,
    *,
    data: bytes,
    kind: ArtifactKind,
    sample_id: str,
    job_id: str | None,
    case_id: str,
    actor: str,
    meta: dict[str, Any] | None = None,
) -> Artifact:
    vault = open_vault(session, actor=actor, case_id=case_id)
    ref = vault.put_bytes(data, actor=actor)

    existing = session.scalar(
        select(Artifact).where(
            Artifact.sample_id == sample_id, Artifact.kind == kind, Artifact.sha256 == ref.sha256
        )
    )
    if existing is not None:
        existing.job_id = job_id or existing.job_id
        existing.meta = meta or {}
        session.flush()
        return existing

    artifact = Artifact(
        sample_id=sample_id,
        job_id=job_id,
        kind=kind,
        sha256=ref.sha256,
        vault_uri=ref.uri,
        size=len(data),
        meta=meta or {},
    )
    session.add(artifact)
    session.flush()
    return artifact


def load_json(session: Session, artifact: Artifact, *, actor: str, case_id: str) -> Any:
    vault = open_vault(session, actor=actor, case_id=case_id)
    return json.loads(vault.read_bytes(artifact.sha256, actor=actor, reason="artifact_read"))


def latest(session: Session, sample_id: str, kind: ArtifactKind) -> Artifact | None:
    return session.scalar(
        select(Artifact)
        .where(Artifact.sample_id == sample_id, Artifact.kind == kind)
        .order_by(Artifact.created_at.desc())
    )
