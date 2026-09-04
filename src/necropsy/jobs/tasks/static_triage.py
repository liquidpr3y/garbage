"""Static triage: the full offline pass over a sample.

PE structure, strings and IOCs, capability detection with ATT&CK mapping,
YARA, and rizin pre-triage if it is installed. Nothing here executes the
sample; every component reads bytes.

The job is written so that any single analyser being unavailable degrades the
result rather than failing it. An analyst on a laptop with no rizin and no
libmagic still gets PE parsing, strings, capabilities and YARA.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from necropsy.analysis import artifacts, capabilities, pe as pe_mod, rizin, strings as strings_mod
from necropsy.analysis import yara_rules
from necropsy.config import get_settings
from necropsy.contracts.host import HostServices
from necropsy.db.models import AnalysisJob
from necropsy.db.repos import samples as samples_repo
from necropsy.enums import (
    ArtifactKind,
    FileType,
    KillChainPhase,
    Producer,
    Severity,
)
from necropsy.intake.service import open_vault
from necropsy.jobs.tasks.base import emit_finding
from necropsy.jobs.tasks.propose import publish_proposals
from necropsy.scoring.proposals import after_static_triage

SECTION_ENTROPY_PACKED = 7.0
MAX_STORED_STRINGS = 5000


def run(session: Session, host: HostServices, job: AnalysisJob) -> dict[str, Any]:
    settings = get_settings()
    sample = samples_repo.get(session, job.sample_id) if job.sample_id else None
    if sample is None:
        raise RuntimeError(f"job {job.id} has no sample to triage")

    actor = host.actor()
    vault = open_vault(session, actor=actor, case_id=job.case_id)
    with vault.open_plaintext(sample.sha256, actor=actor, reason="static_triage") as path:
        pe_info = pe_mod.parse(path) if sample.file_type is FileType.PE else pe_mod.PEInfo()
        harvest = strings_mod.harvest(path)
        yara_result = yara_rules.scan(path)
        rizin_result = rizin.triage(path)

    hits = capabilities.detect(pe_info.imported_functions, harvest.strings)
    quality = capabilities.detection_quality(
        pe_info.import_count, harvest.total_unique, packed=bool(sample.identity.get("high_entropy"))
    )

    _persist_identity(sample, pe_info, rizin_result)
    session.flush()

    _store_artifacts(
        session, job, sample, actor=actor,
        pe_info=pe_info, harvest=harvest, yara_result=yara_result,
        rizin_result=rizin_result, hits=hits, quality=quality,
    )

    counts = {
        "pe": _emit_pe_findings(session, host, job, pe_info),
        "capability": _emit_capability_findings(session, host, job, hits, quality),
        "yara": _emit_yara_findings(session, host, job, yara_result),
        "ioc": _emit_ioc_finding(session, host, job, harvest),
    }

    proposals = after_static_triage(
        sample,
        target_arches=settings.target_arches,
        capability_hits=hits,
        yara_hits=len(yara_result.hits),
        detection_degraded=quality["degraded"],
        ai_disclosure_allowed=_ai_allowed(session, job.case_id),
    )
    publish_proposals(session, host, job, sample, proposals)

    return {
        "pe_parsed_with": pe_info.parsed_with,
        "imports": pe_info.import_count,
        "imphash": pe_info.imphash,
        "strings": harvest.total_unique,
        "iocs": harvest.ioc_count,
        "capabilities": [h.capability.id for h in hits],
        "attack_techniques": sorted({t for h in hits for t in h.capability.attack}),
        "yara_hits": [h.rule for h in yara_result.hits],
        "yara_available": yara_result.available,
        "rizin_available": rizin_result.available,
        "rizin_functions": rizin_result.function_count,
        "detection_degraded": quality["degraded"],
        "findings": counts,
        "proposals": len(proposals),
    }


def _ai_allowed(session: Session, case_id: str) -> bool:
    from necropsy.db.repos import cases as cases_repo

    case = cases_repo.get(session, case_id)
    return bool(case and case.ai_disclosure_allowed)


def _persist_identity(sample: Any, pe_info: pe_mod.PEInfo, rz: rizin.RizinTriage) -> None:
    identity = dict(sample.identity or {})
    identity["static"] = {
        "pe": pe_info.to_dict(),
        "rizin": rz.summary(),
    }
    if pe_info.imphash:
        identity["imphash"] = pe_info.imphash
    sample.identity = identity


def _store_artifacts(
    session: Session,
    job: AnalysisJob,
    sample: Any,
    *,
    actor: str,
    pe_info: pe_mod.PEInfo,
    harvest: strings_mod.StringHarvest,
    yara_result: yara_rules.ScanResult,
    rizin_result: rizin.RizinTriage,
    hits: list[capabilities.CapabilityHit],
    quality: dict[str, Any],
) -> None:
    artifacts.store_json(
        session,
        payload={
            "strings": harvest.strings[:MAX_STORED_STRINGS],
            "iocs": harvest.iocs,
            "summary": harvest.summary(),
        },
        kind=ArtifactKind.STRINGS,
        sample_id=sample.id, job_id=job.id, case_id=job.case_id, actor=actor,
        meta={"count": min(harvest.total_unique, MAX_STORED_STRINGS)},
    )
    artifacts.store_json(
        session,
        payload={
            "pe": pe_info.to_dict(),
            "capabilities": [h.evidence() for h in hits],
            "detection_quality": quality,
            "yara": yara_result.summary(),
            "rizin": rizin_result.summary(),
        },
        kind=ArtifactKind.STATIC_REPORT,
        sample_id=sample.id, job_id=job.id, case_id=job.case_id, actor=actor,
    )


def _emit_pe_findings(
    session: Session, host: HostServices, job: AnalysisJob, pe_info: pe_mod.PEInfo
) -> int:
    if pe_info.parsed_with == "none" or (pe_info.error and not pe_info.sections):
        return 0
    made = 0

    wx = [s for s in pe_info.sections if s.write_execute]
    if wx:
        made += 1
        emit_finding(
            session, host, job,
            producer=Producer.PE, type="pe_writable_executable_section",
            title=f"Writable and executable section: {', '.join(s.name for s in wx)}",
            dedupe_key="pe_wx_section",
            description=(
                "A section marked both writable and executable is the classic "
                "self-modifying unpacking stub. Standard compilers do not emit one."
            ),
            severity=Severity.HIGH, confidence=0.85,
            attack_technique_ids=["T1027.002"],
            kill_chain_phase=KillChainPhase.INSTALLATION,
            evidence={"sections": [s.name for s in wx]},
        )

    hot = [s for s in pe_info.sections if s.entropy >= SECTION_ENTROPY_PACKED]
    if hot:
        made += 1
        emit_finding(
            session, host, job,
            producer=Producer.PE, type="pe_high_entropy_section",
            title=f"{len(hot)} section(s) at packing-level entropy",
            dedupe_key="pe_high_entropy_section",
            description="Compressed, encrypted or packed section contents.",
            severity=Severity.MEDIUM, confidence=0.7,
            attack_technique_ids=["T1027.002"],
            kill_chain_phase=KillChainPhase.INSTALLATION,
            evidence={"sections": [{"name": s.name, "entropy": round(s.entropy, 3)} for s in hot]},
        )

    if pe_info.entrypoint_section and pe_info.entrypoint_section not in (".text", "CODE", ".code"):
        made += 1
        emit_finding(
            session, host, job,
            producer=Producer.PE, type="pe_entrypoint_outside_code",
            title=f"Entry point is in {pe_info.entrypoint_section}, not a code section",
            dedupe_key="pe_entrypoint_outside_code",
            description="Typical of a packer stub prepended to the original image.",
            severity=Severity.MEDIUM, confidence=0.75,
            attack_technique_ids=["T1027.002"],
            kill_chain_phase=KillChainPhase.INSTALLATION,
            evidence={"section": pe_info.entrypoint_section, "rva": pe_info.entrypoint_rva},
        )

    if pe_info.tls_callbacks:
        made += 1
        emit_finding(
            session, host, job,
            producer=Producer.PE, type="pe_tls_callbacks",
            title=f"{len(pe_info.tls_callbacks)} TLS callback(s) registered",
            dedupe_key="pe_tls_callbacks",
            description=(
                "TLS callbacks run before the entry point. Commonly used to defeat a "
                "debugger that breaks on entry, so set breakpoints accordingly."
            ),
            severity=Severity.MEDIUM, confidence=0.8,
            attack_technique_ids=["T1622"],
            kill_chain_phase=KillChainPhase.INSTALLATION,
            evidence={"callbacks": [hex(c) for c in pe_info.tls_callbacks[:16]]},
        )

    if pe_info.pdb_path:
        made += 1
        emit_finding(
            session, host, job,
            producer=Producer.PE, type="pe_debug_path",
            title="Build path left in the debug directory",
            dedupe_key="pe_debug_path",
            description=(
                "A PDB path leaks the build machine's directory layout, and often a "
                "username or project name. Intelligence value rather than a defect: "
                "it clusters samples by builder."
            ),
            severity=Severity.INFO, confidence=1.0,
            evidence={"pdb_path": pe_info.pdb_path},
        )

    if pe_info.overlay_size > 1024:
        made += 1
        entropy = pe_info.overlay_entropy or 0.0
        emit_finding(
            session, host, job,
            producer=Producer.PE, type="pe_overlay",
            title=f"{pe_info.overlay_size} bytes of overlay data appended",
            dedupe_key="pe_overlay",
            description=(
                "Data past the end of the last section. Installers and self-extractors "
                "use it legitimately; so do droppers carrying an embedded payload."
                + (" Overlay entropy is high, so the content is compressed or encrypted."
                   if entropy >= 7.0 else "")
            ),
            severity=Severity.MEDIUM if entropy >= 7.0 else Severity.LOW,
            confidence=0.7,
            attack_technique_ids=["T1027.009"] if entropy >= 7.0 else [],
            kill_chain_phase=KillChainPhase.DELIVERY,
            evidence={"size": pe_info.overlay_size, "entropy": entropy},
        )

    return made


def _emit_capability_findings(
    session: Session,
    host: HostServices,
    job: AnalysisJob,
    hits: list[capabilities.CapabilityHit],
    quality: dict[str, Any],
) -> int:
    for hit in hits:
        capability = hit.capability
        emit_finding(
            session, host, job,
            producer=Producer.CAPABILITY,
            type=f"capability:{capability.id}",
            title=capability.title,
            dedupe_key=f"capability:{capability.id}",
            description=capability.description,
            severity=capability.severity,
            confidence=hit.confidence,
            attack_technique_ids=list(capability.attack),
            kill_chain_phase=capability.kill_chain_phase,
            evidence=hit.evidence(),
        )

    if quality["degraded"]:
        emit_finding(
            session, host, job,
            producer=Producer.CAPABILITY,
            type="capability_coverage_degraded",
            title="Static capability coverage is degraded",
            dedupe_key="capability_coverage_degraded",
            description=quality["note"],
            severity=Severity.INFO, confidence=1.0,
            evidence=quality,
        )
    return len(hits)


def _emit_yara_findings(
    session: Session, host: HostServices, job: AnalysisJob, result: yara_rules.ScanResult
) -> int:
    for hit in result.hits:
        emit_finding(
            session, host, job,
            producer=Producer.YARA,
            type=f"yara:{hit.rule}",
            title=f"YARA: {hit.description}",
            dedupe_key=f"yara:{hit.rule}",
            description=f"Rule {hit.rule} matched.",
            severity=hit.severity,
            confidence=hit.confidence,
            attack_technique_ids=hit.attack,
            kill_chain_phase=hit.kill_chain_phase,
            evidence={"rule": hit.rule, "tags": hit.tags, "strings": hit.matched_strings},
        )
    return len(result.hits)


def _emit_ioc_finding(
    session: Session, host: HostServices, job: AnalysisJob, harvest: strings_mod.StringHarvest
) -> int:
    network = {
        k: v for k, v in harvest.iocs.items() if k in ("url", "ipv4", "domain", "user_agent")
    }
    if not network:
        return 0
    total = sum(len(v) for v in network.values())
    emit_finding(
        session, host, job,
        producer=Producer.STRINGS,
        type="network_iocs",
        title=f"{total} network indicator(s) in strings",
        dedupe_key="network_iocs",
        description=(
            "Hardcoded network indicators. Hunt these in the SIEM before detonating: "
            "an existing hit changes the case from analysis to incident response."
        ),
        severity=Severity.MEDIUM, confidence=0.6,
        attack_technique_ids=["T1071.001"] if network.get("url") else [],
        kill_chain_phase=KillChainPhase.COMMAND_AND_CONTROL,
        evidence=network,
    )
    return 1
