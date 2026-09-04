"""Turn a completed stage into risk-scored next steps for the operator.

This is the orchestration loop the pentest module already uses: results push
into the next stage, the human chooses, and blast radius is visible before the
click. Nothing here executes anything -- proposals are inert rows until someone
accepts one.

Kinds a later phase implements are still proposed, marked ``available=False``,
so the GUI can grey them out. Showing the whole decision space and saying what
is not built yet is more useful than silently offering three options and
pretending the others do not exist.
"""

from __future__ import annotations

from necropsy.contracts.risk import ActionProposal, score_factors
from necropsy.db.models import Sample
from necropsy.enums import Arch, FileType, JobKind, Severity
from necropsy.scoring import rules

# Kinds not yet implemented, and the phase that lands each.
PLANNED: dict[str, str] = {
    JobKind.DETONATE.value: "Phase 3 (VMware Fusion sandbox)",
    JobKind.AI_SUMMARISE.value: "Phase 5 (Claude API)",
}

DETONATABLE_WITHOUT_NATIVE_ARCH = {
    FileType.OFFICE,
    FileType.SCRIPT,
    FileType.SHORTCUT,
    FileType.PDF,
}


def _tooling_note(kind: JobKind) -> str | None:
    """Phase 2 jobs depend on external analysers that may not be installed.

    An operator should be told "Ghidra is not installed here" rather than being
    offered a button that fails, so unavailability is surfaced on the proposal
    the same way an unimplemented phase is.
    """
    if kind is JobKind.GHIDRA_DECOMPILE:
        from necropsy.analysis.ghidra import have_ghidra

        if not have_ghidra():
            return "Ghidra not installed; set NECROPSY_GHIDRA_HOME"
    if kind is JobKind.YARA_SCAN:
        from necropsy.analysis.yara_rules import have_yara

        if not have_yara():
            return "yara-python not installed; pip install necropsy[analysis]"
    return None


def _proposal(
    kind: JobKind,
    title: str,
    rationale: str,
    factors: list,
    *,
    cost_s: int | None = None,
    params: dict | None = None,
) -> ActionProposal:
    planned_note = PLANNED.get(kind.value)
    reason = f"Not implemented until {planned_note}" if planned_note else _tooling_note(kind)
    return ActionProposal(
        kind=kind.value,
        title=title,
        rationale=rationale,
        risk=score_factors(rules.BASE_RISK.get(kind.value, 1.0), factors),
        estimated_cost_s=cost_s,
        params=params or {},
        available=reason is None,
        unavailable_reason=reason,
    )


def after_identify(
    sample: Sample,
    *,
    target_arches: list[str],
    seen_in_other_cases: int = 0,
    ai_disclosure_allowed: bool = False,
) -> list[ActionProposal]:
    detail = sample.identity or {}
    packed = bool(detail.get("high_entropy"))
    unsigned = detail.get("authenticode_signed") is False
    macro = bool(detail.get("has_vba_macro"))

    common: list = []
    if packed:
        common.append(rules.packed())
    if unsigned:
        common.append(rules.unsigned())
    if macro:
        common.append(rules.office_macro())
    if sample.file_type is FileType.UNKNOWN:
        common.append(rules.unknown_type())
    if seen_in_other_cases:
        common.append(rules.known_sample())

    proposals = [
        _proposal(
            JobKind.HASH_PIVOT,
            "Pivot on hashes across all cases",
            "Look for this exact sample and near neighbours by TLSH in every other case. "
            "Cheap, offline, and often reframes a case before any deeper analysis.",
            [],
            cost_s=2,
        ),
        _proposal(
            JobKind.STATIC_TRIAGE,
            "Static triage (rizin pre-triage, PE parsing, YARA)",
            "Fast structural pass before committing to a full decompile. "
            + ("Entropy suggests packing, so expect a thin import table. " if packed else ""),
            common,
            cost_s=45,
        ),
        _proposal(
            JobKind.GHIDRA_DECOMPILE,
            "Full Ghidra decompile pass",
            "Headless analysis and decompilation of every function. Slow, offline, "
            "no execution -- the safe way to answer what the sample actually does.",
            common,
            cost_s=480,
        ),
    ]

    proposals.append(_detonation_proposal(sample, common, target_arches, egress=False))
    proposals.append(_detonation_proposal(sample, common, target_arches, egress=True))

    ai_factors = [*common, rules.third_party_disclosure()]
    proposals.append(
        _proposal(
            JobKind.AI_SUMMARISE,
            "AI summary of decompiled functions",
            "Send decompiled code and strings to the Claude API for summarisation. "
            + (
                "This case permits third-party disclosure."
                if ai_disclosure_allowed
                else "Blocked: this case has ai_disclosure_allowed set to false."
            ),
            ai_factors,
            cost_s=60,
        )
    )
    return proposals


def _detonation_proposal(
    sample: Sample,
    common: list,
    target_arches: list[str],
    *,
    egress: bool,
) -> ActionProposal:
    factors = list(common)
    factors.append(rules.egress_allowed() if egress else rules.network_isolated())

    native_needed = sample.file_type in {FileType.PE, FileType.ELF, FileType.MACHO}
    mismatch = (
        native_needed
        and sample.arch not in (Arch.UNKNOWN, Arch.NOT_APPLICABLE)
        and sample.arch.value not in target_arches
    )
    if mismatch:
        factors.append(rules.arch_mismatch(sample.arch.value, target_arches))

    if mismatch:
        fidelity = (
            f"Fidelity warning: this is a {sample.arch.value} binary and the lab runs "
            f"{'/'.join(target_arches) or 'nothing'}. It will execute under emulation, if at "
            "all. A quiet run is not evidence that the sample is benign."
        )
    elif not native_needed and sample.file_type in DETONATABLE_WITHOUT_NATIVE_ARCH:
        fidelity = (
            "Runs through a native interpreter or runtime, so behaviour on the ARM lab is "
            "representative."
        )
    else:
        fidelity = "Architecture matches an available target."

    egress_note = (
        "Egress permitted: the sample can reach live C2, which confirms infrastructure but "
        "tells the operator your lab exists and attributes it to your IP."
        if egress
        else "Host-only networking: no egress, no attribution, no live C2 confirmation."
    )

    return _proposal(
        JobKind.DETONATE,
        f"Detonate in sandbox ({'egress permitted' if egress else 'isolated'})",
        f"{egress_note} {fidelity}",
        factors,
        cost_s=300,
        params={"egress": egress},
    )


def after_static_triage(
    sample: Sample,
    *,
    target_arches: list[str],
    capability_hits: list,
    yara_hits: int,
    detection_degraded: bool,
    ai_disclosure_allowed: bool = False,
) -> list[ActionProposal]:
    """What to offer once the offline pass is done.

    The interesting case is a degraded result. When the import table is a
    packer stub, the honest next step is a decompile that can see past it --
    not a detonation whose quiet outcome would be unreadable. That reasoning
    goes in the rationale, where the operator can weigh it.
    """
    detail = sample.identity or {}
    packed = bool(detail.get("high_entropy"))

    common: list = []
    if packed:
        common.append(rules.packed())
    if detail.get("authenticode_signed") is False:
        common.append(rules.unsigned())
    if detail.get("has_vba_macro"):
        common.append(rules.office_macro())

    severities = {h.capability.severity for h in capability_hits}
    dangerous = severities & {Severity.HIGH, Severity.CRITICAL}

    if dangerous:
        capability_note = (
            f"Static analysis found {len(capability_hits)} capabilities, "
            f"{len([h for h in capability_hits if h.capability.severity in (Severity.HIGH, Severity.CRITICAL)])} "
            "of them high or critical. "
        )
    elif capability_hits:
        capability_note = f"Static analysis found {len(capability_hits)} low-severity capabilities. "
    else:
        capability_note = "Static analysis surfaced no capability indicators. "

    if detection_degraded:
        capability_note += (
            "Coverage was degraded, so that is a limit of visibility rather than a clean bill. "
        )

    proposals = [
        _proposal(
            JobKind.GHIDRA_DECOMPILE,
            "Full Ghidra decompile pass",
            capability_note
            + (
                "A decompile sees through the thin import table and is the right next step."
                if detection_degraded
                else "Confirms what the capability indicators imply, at function level."
            ),
            common,
            cost_s=480,
        ),
        _proposal(
            JobKind.YARA_SCAN,
            "Re-scan with current YARA rules",
            f"{yara_hits} rule(s) matched on the last pass. Cheap to repeat after "
            "adding or editing rules.",
            [],
            cost_s=5,
        ),
    ]

    proposals.append(_detonation_proposal(sample, common, target_arches, egress=False))
    proposals.append(_detonation_proposal(sample, common, target_arches, egress=True))
    proposals.append(
        _proposal(
            JobKind.AI_SUMMARISE,
            "AI summary of decompiled functions",
            "Summarise recovered functions via the Claude API. "
            + (
                "This case permits third-party disclosure."
                if ai_disclosure_allowed
                else "Blocked: this case has ai_disclosure_allowed set to false."
            ),
            [*common, rules.third_party_disclosure()],
            cost_s=60,
        )
    )
    return proposals


def after_decompile(
    sample: Sample,
    *,
    target_arches: list[str],
    function_count: int,
    new_capabilities: list,
    ai_disclosure_allowed: bool = False,
) -> list[ActionProposal]:
    detail = sample.identity or {}
    common: list = []
    if detail.get("high_entropy"):
        common.append(rules.packed())

    note = f"{function_count} function(s) recovered. "
    if new_capabilities:
        note += (
            f"{len(new_capabilities)} capability indicator(s) were visible only in the "
            "decompilation, not the import table -- the sample resolves those APIs at runtime. "
        )

    proposals = [
        _proposal(
            JobKind.AI_SUMMARISE,
            "AI summary of decompiled functions",
            note
            + (
                "This case permits third-party disclosure."
                if ai_disclosure_allowed
                else "Blocked: this case has ai_disclosure_allowed set to false."
            ),
            [*common, rules.third_party_disclosure()],
            cost_s=60,
        ),
    ]
    proposals.append(_detonation_proposal(sample, common, target_arches, egress=False))
    proposals.append(_detonation_proposal(sample, common, target_arches, egress=True))
    return proposals
