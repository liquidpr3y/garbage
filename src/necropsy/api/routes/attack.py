"""ATT&CK views: the per-case heatmap, the catalogue, and Sigma status.

The heatmap endpoint returns the whole matrix shape the GUI needs -- tactic
columns in MITRE's own order, techniques rolled up from sub-techniques, each
cell carrying its evidence grade and caveat. Rendering is the GUI's job;
deciding what the evidence is worth is not.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from necropsy.api.deps import db_session
from necropsy.attack import coverage as coverage_mod
from necropsy.attack.catalogue import KILL_CHAIN_NOTE, get_catalogue
from necropsy.db.repos import cases as cases_repo
from necropsy.schemas.attack import AttackStatus, TechniqueOut

router = APIRouter(tags=["attack"])


@router.get("/cases/{case_id}/attack")
def case_attack_coverage(
    case_id: str,
    sysmon_codes: str | None = Query(
        default=None,
        description="Comma-separated Sysmon event IDs this lab collects; "
        "defaults to what Necropsy queries for",
    ),
    session: Session = Depends(db_session),
) -> dict[str, Any]:
    """The per-case technique heatmap, plus what the lab could not have seen."""
    if cases_repo.get(session, case_id) is None:
        raise HTTPException(404, "case not found")

    collected = (
        [c.strip() for c in sysmon_codes.split(",") if c.strip()] if sysmon_codes else None
    )
    return coverage_mod.build(session, case_id, collected_sysmon_codes=collected).to_dict()


@router.get("/attack/tactics")
def tactics() -> dict[str, Any]:
    """Matrix columns in MITRE's order, with the kill chain phase each maps to."""
    catalogue = get_catalogue()
    return {
        "attack_version": catalogue.attack_version,
        "kill_chain_note": KILL_CHAIN_NOTE,
        "tactics": [
            {
                **tactic,
                "kill_chain_phase": (
                    catalogue.kill_chain_phase(tactic["shortname"]).value
                    if catalogue.kill_chain_phase(tactic["shortname"])
                    else None
                ),
            }
            for tactic in catalogue.tactics()
        ],
    }


@router.get("/attack/techniques/{technique_id}", response_model=TechniqueOut)
def technique(technique_id: str) -> Any:
    catalogue = get_catalogue()
    found = catalogue.get(technique_id)
    if found is None:
        raise HTTPException(404, f"{technique_id} is not in ATT&CK {catalogue.attack_version}")
    return TechniqueOut(
        **found.to_dict(),
        subtechniques=[t.id for t in catalogue.subtechniques_of(found.id)],
        kill_chain_phase=(
            catalogue.kill_chain_for_technique(found.id).value
            if catalogue.kill_chain_for_technique(found.id)
            else None
        ),
    )


@router.get("/attack/sigma/rules")
def sigma_rules() -> dict[str, Any]:
    """What the Sigma corpus currently loaded can detect."""
    from necropsy.attack.sigma import compile_rules, have_sigma

    if not have_sigma():
        return {"available": False, "rules": [], "sources": []}

    rules, sources = compile_rules()
    return {
        "available": True,
        "rules": [
            {
                "id": r.id, "title": r.title, "level": r.level, "status": r.status,
                "source": r.source, "attack_techniques": r.attack_techniques,
                "attack_tactics": r.attack_tactics,
            }
            for r in rules
        ],
        "sources": [
            {"name": s.name, "packaged": s.packaged, "rules": s.rule_count, "error": s.error}
            for s in sources
        ],
    }


@router.get("/attack/status", response_model=AttackStatus)
def attack_status() -> Any:
    from necropsy.attack.sigma import compile_rules, have_sigma
    from necropsy.sinks import get_sink

    catalogue = get_catalogue()
    rules, sources = compile_rules() if have_sigma() else ([], [])
    return AttackStatus(
        attack_version=catalogue.attack_version,
        technique_count=len(catalogue),
        tactic_count=len(catalogue.tactics()),
        sigma_available=have_sigma(),
        sigma_rule_count=len(rules),
        sigma_sources=[s.name for s in sources],
        finding_sink=get_sink().name,
    )
