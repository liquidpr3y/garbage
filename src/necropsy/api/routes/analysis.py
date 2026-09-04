"""Static analysis views -- what the GUI's disassembly/decompile panel binds to.

Large outputs (strings dumps, decompilation exports) live in the vault as
artifacts rather than in SQLite, so these endpoints read them back through the
audited vault path. Functions are rows, so they page and search without
touching the blob at all.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from necropsy.analysis import artifacts as artifact_store
from necropsy.analysis.capabilities import CATALOGUE
from necropsy.analysis.ghidra import have_ghidra
from necropsy.analysis.yara_rules import have_yara, rule_files
from necropsy.api.deps import db_session, host_services
from necropsy.contracts.host import HostServices
from necropsy.db.models import DecompiledFunction
from necropsy.db.repos import samples as samples_repo
from necropsy.enums import ArtifactKind
from necropsy.schemas.analysis import (
    CapabilityDescriptor,
    FunctionDetail,
    FunctionSummary,
    ToolingStatus,
)

router = APIRouter(tags=["analysis"])


def _sample_or_404(session: Session, sha256: str):  # type: ignore[no-untyped-def]
    sample = samples_repo.get_by_sha256(session, sha256.lower())
    if sample is None:
        raise HTTPException(404, "sample not found")
    return sample


def _artifact_payload(
    session: Session, host: HostServices, sha256: str, kind: ArtifactKind
) -> Any:
    sample = _sample_or_404(session, sha256)
    artifact = artifact_store.latest(session, sample.id, kind)
    if artifact is None:
        raise HTTPException(
            404,
            f"no {kind.value} artifact for this sample; run static triage first",
        )
    case_id = _first_case_id(session, sample.id)
    payload = artifact_store.load_json(session, artifact, actor=host.actor(), case_id=case_id)
    session.commit()  # the vault read is auditable and must be durable
    return payload


def _first_case_id(session: Session, sample_id: str) -> str:
    cases = samples_repo.other_cases(session, sample_id)
    return cases[0].id if cases else ""


@router.get("/samples/{sha256}/static")
def static_report(
    sha256: str,
    session: Session = Depends(db_session),
    host: HostServices = Depends(host_services),
) -> Any:
    """PE structure, capability hits with ATT&CK mapping, YARA and rizin output."""
    return _artifact_payload(session, host, sha256, ArtifactKind.STATIC_REPORT)


@router.get("/samples/{sha256}/strings")
def sample_strings(
    sha256: str,
    contains: str | None = Query(default=None, description="Case-insensitive filter"),
    limit: int = Query(default=1000, le=20000),
    session: Session = Depends(db_session),
    host: HostServices = Depends(host_services),
) -> Any:
    payload = _artifact_payload(session, host, sha256, ArtifactKind.STRINGS)
    values: list[str] = payload.get("strings", [])
    if contains:
        needle = contains.lower()
        values = [v for v in values if needle in v.lower()]
    return {
        "iocs": payload.get("iocs", {}),
        "summary": payload.get("summary", {}),
        "matched": len(values),
        "strings": values[:limit],
    }


@router.get("/samples/{sha256}/functions", response_model=list[FunctionSummary])
def list_functions(
    sha256: str,
    q: str | None = Query(default=None, description="Match function name or decompiled body"),
    include_thunks: bool = False,
    limit: int = Query(default=200, le=2000),
    offset: int = 0,
    session: Session = Depends(db_session),
) -> Any:
    sample = _sample_or_404(session, sha256)
    stmt = select(DecompiledFunction).where(DecompiledFunction.sample_id == sample.id)
    if not include_thunks:
        stmt = stmt.where(DecompiledFunction.is_thunk.is_(False))
    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(
            or_(DecompiledFunction.name.ilike(pattern),
                DecompiledFunction.decompiled.ilike(pattern))
        )
    stmt = stmt.order_by(DecompiledFunction.size.desc()).limit(limit).offset(offset)
    return [FunctionSummary(**row.to_summary()) for row in session.scalars(stmt)]


@router.get("/functions/{function_id}", response_model=FunctionDetail)
def get_function(function_id: str, session: Session = Depends(db_session)) -> Any:
    row = session.get(DecompiledFunction, function_id)
    if row is None:
        raise HTTPException(404, "function not found")
    return row


@router.get("/samples/{sha256}/function-stats")
def function_stats(sha256: str, session: Session = Depends(db_session)) -> dict[str, Any]:
    sample = _sample_or_404(session, sha256)
    base = select(func.count()).select_from(DecompiledFunction).where(
        DecompiledFunction.sample_id == sample.id
    )
    total = int(session.scalar(base) or 0)
    thunks = int(session.scalar(base.where(DecompiledFunction.is_thunk.is_(True))) or 0)
    decompiled = int(
        session.scalar(base.where(DecompiledFunction.decompiled.is_not(None))) or 0
    )
    summarised = int(
        session.scalar(base.where(DecompiledFunction.ai_summary.is_not(None))) or 0
    )
    return {
        "total": total,
        "thunks": thunks,
        "decompiled": decompiled,
        "ai_summarised": summarised,
    }


@router.get("/analysis/tooling", response_model=ToolingStatus)
def tooling_status() -> Any:
    """What this install can actually do -- the GUI greys out the rest."""
    from necropsy.analysis.pe import have_lief
    from necropsy.analysis.rizin import have_rizin, rizin_binary
    from necropsy.intake.hashing import have_tlsh
    from necropsy.intake.identify import have_magic

    sources = [{"name": p.name, "packaged": packaged} for p, packaged in rule_files()]
    return ToolingStatus(
        lief=have_lief(),
        yara=have_yara(),
        tlsh=have_tlsh(),
        libmagic=have_magic(),
        rizin=have_rizin(),
        rizin_path=rizin_binary(),
        ghidra=have_ghidra(),
        yara_rule_sources=sources,
    )


@router.get("/analysis/capabilities", response_model=list[CapabilityDescriptor])
def capability_catalogue() -> Any:
    """The detection catalogue, so the GUI can explain a finding without a lookup table."""
    return [
        CapabilityDescriptor(
            id=c.id,
            title=c.title,
            description=c.description,
            severity=c.severity,
            kill_chain_phase=c.kill_chain_phase,
            attack_technique_ids=list(c.attack),
            indicator_count=len(c.imports) + len(c.strings),
            min_hits=c.min_hits,
        )
        for c in CATALOGUE
    ]
