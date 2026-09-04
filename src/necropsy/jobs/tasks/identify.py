"""The Phase 1 analysis job.

Reads the sample back out of the vault (which exercises the vault read path and
its audit trail on every sample, not just in Phase 3), identifies it properly,
records findings, and proposes what the operator might do next.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from necropsy.config import get_settings
from necropsy.contracts.events import Event, EventType, case_channel
from necropsy.contracts.host import HostServices
from necropsy.db.models import AnalysisJob
from necropsy.db.repos import actions as actions_repo, cases as cases_repo, samples as samples_repo
from necropsy.enums import Arch, FileType, JobKind, Producer, Severity
from necropsy.intake.identify import PACKED_ENTROPY_THRESHOLD, identify, is_probably_packed
from necropsy.intake.service import open_vault
from necropsy.jobs.tasks.base import emit_finding
from necropsy.scoring.proposals import after_identify

NATIVE_TYPES = {FileType.PE, FileType.ELF, FileType.MACHO}


def run(session: Session, host: HostServices, job: AnalysisJob) -> dict[str, Any]:
    settings = get_settings()
    sample = samples_repo.get(session, job.sample_id) if job.sample_id else None
    if sample is None:
        raise RuntimeError(f"job {job.id} has no sample to identify")

    vault = open_vault(session, actor=host.actor(), case_id=job.case_id)
    with vault.open_plaintext(sample.sha256, actor=host.actor(), reason="identify") as path:
        ident = identify(path)

    detail = dict(ident.detail)
    detail["high_entropy"] = is_probably_packed(ident)

    sample.file_type = ident.file_type
    sample.arch = ident.arch
    sample.mime = ident.mime
    sample.magic = ident.magic
    sample.entropy = ident.entropy
    sample.identity = detail
    session.flush()

    other_cases = samples_repo.other_cases(session, sample.id, exclude_case_id=job.case_id)
    findings_made: list[str] = []

    if detail.get("high_entropy"):
        findings_made.append(
            emit_finding(
                session, host, job,
                producer=Producer.INTAKE,
                type="high_entropy",
                title=f"High entropy ({ident.entropy}) -- likely packed or encrypted",
                dedupe_key=f"high_entropy:{sample.sha256}",
                description=(
                    f"Entropy {ident.entropy} is at or above the {PACKED_ENTROPY_THRESHOLD} "
                    "triage threshold. Expect a thin import table and little useful static "
                    "string content until the sample is unpacked."
                ),
                severity=Severity.MEDIUM,
                confidence=0.6,
                evidence={"entropy": ident.entropy, "sections": detail.get("section_names")},
            ).type
        )

    if detail.get("authenticode_signed") is False:
        findings_made.append(
            emit_finding(
                session, host, job,
                producer=Producer.PE,
                type="pe_no_signature",
                title="PE has no Authenticode signature",
                dedupe_key=f"pe_no_signature:{sample.sha256}",
                description=(
                    "Unsigned is not damning on its own. It matters when the binary "
                    "presents itself as a vendor product, or when it is found in a "
                    "location where signed binaries are the norm."
                ),
                severity=Severity.LOW,
                confidence=0.9,
                evidence={"machine": detail.get("machine"), "is_dll": detail.get("is_dll")},
            ).type
        )

    if detail.get("has_vba_macro"):
        findings_made.append(
            emit_finding(
                session, host, job,
                producer=Producer.INTAKE,
                type="office_vba_macro",
                title="Office document contains a VBA macro project",
                dedupe_key=f"office_vba_macro:{sample.sha256}",
                description=(
                    "Macro-bearing documents execute faithfully on the ARM lab, so this "
                    "sample is a good candidate for dynamic analysis despite the "
                    "architecture constraint."
                ),
                severity=Severity.MEDIUM,
                confidence=0.9,
            ).type
        )

    mismatch = (
        ident.file_type in NATIVE_TYPES
        and ident.arch not in (Arch.UNKNOWN, Arch.NOT_APPLICABLE)
        and ident.arch.value not in settings.target_arches
    )
    if mismatch:
        findings_made.append(
            emit_finding(
                session, host, job,
                producer=Producer.INTAKE,
                type="arch_mismatch_risk",
                title=(
                    f"{ident.arch.value} sample, lab targets are "
                    f"{'/'.join(settings.target_arches) or 'none'}"
                ),
                dedupe_key=f"arch_mismatch_risk:{sample.sha256}",
                description=(
                    "This binary cannot run natively on any configured detonation target. "
                    "Under emulation it may fail outright or silently go dormant, and "
                    "dormancy is indistinguishable from benignity. Treat any quiet "
                    "sandbox run of this sample as inconclusive, not clean. Static "
                    "analysis carries the weight here."
                ),
                severity=Severity.MEDIUM,
                confidence=0.95,
                evidence={
                    "sample_arch": ident.arch.value,
                    "target_arches": settings.target_arches,
                },
            ).type
        )

    if other_cases:
        names = ", ".join(c.name for c in other_cases[:5])
        findings_made.append(
            emit_finding(
                session, host, job,
                producer=Producer.CORRELATION,
                type="known_sample_reappearance",
                title=f"Sample also appears in {len(other_cases)} other case(s)",
                dedupe_key=f"known_sample_reappearance:{sample.sha256}",
                description=f"Previously seen in: {names}.",
                severity=Severity.INFO,
                confidence=1.0,
                evidence={"case_ids": [c.id for c in other_cases]},
            ).type
        )

    case = cases_repo.get(session, job.case_id)
    proposals = after_identify(
        sample,
        target_arches=settings.target_arches,
        seen_in_other_cases=len(other_cases),
        ai_disclosure_allowed=bool(case and case.ai_disclosure_allowed),
    )

    # Re-running identification replaces its old advice rather than stacking a
    # second copy of it on the operator's queue.
    actions_repo.supersede_open(session, job.case_id, [p.kind for p in proposals])
    for proposal in proposals:
        action = actions_repo.create_from_proposal(
            session, proposal, case_id=job.case_id, sample_id=sample.id, origin_job_id=job.id
        )
        host.publish(
            case_channel(job.case_id),
            Event(
                type=EventType.ACTION_PROPOSED,
                case_id=job.case_id,
                payload={
                    "action_id": action.id,
                    "kind": action.kind,
                    "title": action.title,
                    "risk_score": action.risk_score,
                    "risk_band": action.risk_band,
                    "available": action.available,
                },
            ),
        )

    return {
        "file_type": ident.file_type.value,
        "arch": ident.arch.value,
        "entropy": ident.entropy,
        "findings": findings_made,
        "proposals": len(proposals),
        "next_kinds": [JobKind.HASH_PIVOT.value],
    }
