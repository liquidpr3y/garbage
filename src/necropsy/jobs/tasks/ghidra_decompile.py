"""Full Ghidra decompilation pass.

The expensive, offline, definitive static step. Two things happen beyond
storing the decompilation:

1. Functions are persisted as rows so the GUI can page and search them, and so
   Phase 5 has somewhere to attach a per-function AI summary.
2. Capability detection is re-run over the *decompiled text and call graph*.
   That is the whole point of paying for a decompile on a sample that resolves
   its APIs at runtime: `GetProcAddress("CreateRemoteThread")` is invisible to
   import-table analysis but plain in the decompilation. Capabilities found
   only here are reported as such.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from necropsy.analysis import artifacts, capabilities, ghidra
from necropsy.config import get_settings
from necropsy.contracts.host import HostServices
from necropsy.db.models import AnalysisJob, DecompiledFunction
from necropsy.db.repos import cases as cases_repo, samples as samples_repo
from necropsy.enums import ArtifactKind, KillChainPhase, Producer, Severity
from necropsy.intake.service import open_vault
from necropsy.jobs.tasks.base import emit_finding
from necropsy.jobs.tasks.propose import publish_proposals
from necropsy.scoring.proposals import after_decompile

# Identifier-shaped tokens in decompiled C, used to re-run capability matching.
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,63}")
_WHITESPACE = re.compile(r"\s+")


class GhidraNotInstalled(RuntimeError):
    pass


def run(session: Session, host: HostServices, job: AnalysisJob) -> dict[str, Any]:
    settings = get_settings()
    sample = samples_repo.get(session, job.sample_id) if job.sample_id else None
    if sample is None:
        raise RuntimeError(f"job {job.id} has no sample to decompile")

    actor = host.actor()
    vault = open_vault(session, actor=actor, case_id=job.case_id)
    with vault.open_plaintext(sample.sha256, actor=actor, reason="ghidra_decompile") as path:
        result = ghidra.decompile(path)

    if not result.available:
        # Not a failure of the sample or the platform: the operator's machine
        # simply has no Ghidra. Say so plainly rather than failing the job.
        raise GhidraNotInstalled(result.error or "Ghidra unavailable")
    if result.error:
        raise RuntimeError(result.error)

    stored = _persist_functions(session, sample.id, job.id, result.functions)
    artifacts.store_json(
        session,
        payload={"program": result.program, "functions": result.functions},
        kind=ArtifactKind.DECOMPILATION,
        sample_id=sample.id, job_id=job.id, case_id=job.case_id, actor=actor,
        meta={"function_count": len(result.functions), "truncated": result.truncated},
    )

    known = _known_capability_ids(session, job.case_id)
    hits = _detect_in_decompilation(result.functions)
    new_hits = [h for h in hits if h.capability.id not in known]

    for hit in hits:
        capability = hit.capability
        only_here = capability.id in {h.capability.id for h in new_hits}
        emit_finding(
            session, host, job,
            producer=Producer.GHIDRA,
            type=f"capability:{capability.id}",
            title=capability.title
            + (" (visible only after decompilation)" if only_here else ""),
            dedupe_key=f"capability:{capability.id}",
            description=capability.description
            + (
                "\n\nThis was not visible in the import table, which means the sample "
                "resolves it at runtime. Static import analysis alone would have missed it."
                if only_here
                else ""
            ),
            severity=capability.severity,
            confidence=hit.confidence,
            attack_technique_ids=list(capability.attack),
            kill_chain_phase=capability.kill_chain_phase,
            evidence={**hit.evidence(), "source": "decompilation"},
        )

    emit_finding(
        session, host, job,
        producer=Producer.GHIDRA,
        type="decompilation_complete",
        title=f"{stored} function(s) decompiled",
        dedupe_key="decompilation_complete",
        description=(
            f"Ghidra recovered {result.total_functions} function(s) as "
            f"{result.program.get('language')}."
            + (" Output was truncated at the configured cap." if result.truncated else "")
        ),
        severity=Severity.INFO, confidence=1.0,
        kill_chain_phase=None,
        evidence=result.summary(),
    )

    case = cases_repo.get(session, job.case_id)
    proposals = after_decompile(
        sample,
        target_arches=settings.target_arches,
        function_count=stored,
        new_capabilities=new_hits,
        ai_disclosure_allowed=bool(case and case.ai_disclosure_allowed),
    )
    publish_proposals(session, host, job, sample, proposals)

    return {
        **result.summary(),
        "stored_functions": stored,
        "capabilities": [h.capability.id for h in hits],
        "capabilities_only_in_decompilation": [h.capability.id for h in new_hits],
        "attack_techniques": sorted({t for h in hits for t in h.capability.attack}),
    }


def _persist_functions(
    session: Session, sample_id: str, job_id: str, functions: list[dict[str, Any]]
) -> int:
    existing = {
        row.address: row
        for row in session.scalars(
            select(DecompiledFunction).where(DecompiledFunction.sample_id == sample_id)
        )
    }

    for entry in functions:
        address = str(entry.get("address", ""))
        if not address:
            continue
        decompiled = entry.get("decompiled")
        row = existing.get(address)
        values = {
            "name": str(entry.get("name", "?"))[:300],
            "size": int(entry.get("size", 0) or 0),
            "is_thunk": bool(entry.get("is_thunk")),
            "calling_convention": (entry.get("calling_convention") or None),
            "parameter_count": int(entry.get("parameter_count", 0) or 0),
            "calls": list(entry.get("calls") or []),
            "decompiled": decompiled,
            "decompile_error": entry.get("decompile_error"),
            "code_sha256": _normalised_hash(decompiled),
            "job_id": job_id,
        }
        if row is None:
            session.add(DecompiledFunction(sample_id=sample_id, address=address, **values))
        else:
            for key, value in values.items():
                setattr(row, key, value)
    session.flush()
    return len(functions)


def _normalised_hash(code: str | None) -> str | None:
    """Hash the decompiled body with whitespace collapsed.

    Ghidra's naming of locals varies run to run, but the shape does not.
    Collapsing whitespace is a cheap first-order normalisation that makes
    identical function bodies across samples comparable.
    """
    if not code:
        return None
    normalised = _WHITESPACE.sub(" ", code).strip()
    return hashlib.sha256(normalised.encode()).hexdigest()


def _detect_in_decompilation(functions: list[dict[str, Any]]) -> list[Any]:
    """Capability matching over identifiers in the decompilation and call graph."""
    identifiers: set[str] = set()
    text_fragments: list[str] = []
    for entry in functions:
        identifiers.update(str(c) for c in entry.get("calls") or [])
        identifiers.add(str(entry.get("name", "")))
        code = entry.get("decompiled")
        if code:
            identifiers.update(_IDENTIFIER.findall(code))
            text_fragments.append(code)
    return capabilities.detect(sorted(identifiers), text_fragments)


def _known_capability_ids(session: Session, case_id: str) -> set[str]:
    from necropsy.db.models import Finding

    rows = session.scalars(
        select(Finding.type).where(
            Finding.case_id == case_id, Finding.type.like("capability:%")
        )
    )
    return {row.split(":", 1)[1] for row in rows}
