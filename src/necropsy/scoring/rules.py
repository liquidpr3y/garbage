"""Risk factors and per-action baselines.

Risk here means blast radius and consequence, the same thing it means in the
pentest module -- that is the point of sharing the vocabulary. Note one
deliberate inclusion: an architecture mismatch raises the risk of a detonation
even though it makes it *less* dangerous to run, because the operational
hazard is a false negative. A sample that goes dormant under emulation looks
exactly like a benign one, and acting on that is worse than not running it.
"""

from __future__ import annotations

from necropsy.contracts.risk import RiskFactor
from necropsy.enums import JobKind

BASE_RISK: dict[str, float] = {
    JobKind.IDENTIFY.value: 0.2,
    JobKind.HASH_PIVOT.value: 0.3,
    JobKind.STATIC_TRIAGE.value: 1.0,
    JobKind.YARA_SCAN.value: 0.8,
    JobKind.GHIDRA_DECOMPILE.value: 1.0,
    JobKind.SIGMA_SWEEP.value: 0.3,
    JobKind.AI_SUMMARISE.value: 2.0,
    JobKind.DETONATE.value: 5.0,
}


def packed() -> RiskFactor:
    return RiskFactor(
        code="sample_packed",
        label="Packed or encrypted contents (high entropy)",
        weight=1.2,
    )


def unsigned() -> RiskFactor:
    return RiskFactor(code="pe_unsigned", label="No Authenticode signature", weight=0.5)


def office_macro() -> RiskFactor:
    return RiskFactor(code="office_macro", label="Document carries a VBA macro", weight=1.0)


def unknown_type() -> RiskFactor:
    return RiskFactor(code="unknown_file_type", label="File type not identified", weight=0.5)


def arch_mismatch(sample_arch: str, target_arches: list[str]) -> RiskFactor:
    return RiskFactor(
        code="arch_mismatch",
        label=(
            f"{sample_arch} sample against {'/'.join(target_arches) or 'no'} target: "
            "emulated execution, dormancy is not evidence of benignity"
        ),
        weight=1.5,
    )


def egress_allowed() -> RiskFactor:
    return RiskFactor(
        code="egress_allowed",
        label="Live network egress: C2 contact is attributable to your lab",
        weight=3.0,
    )


def network_isolated() -> RiskFactor:
    return RiskFactor(
        code="network_isolated",
        label="Host-only network, no egress",
        weight=1.0,
        direction=-1,
    )


def known_sample() -> RiskFactor:
    return RiskFactor(
        code="known_sample",
        label="Already analysed in another case",
        weight=0.5,
        direction=-1,
    )


def third_party_disclosure() -> RiskFactor:
    return RiskFactor(
        code="third_party_disclosure",
        label="Sample-derived content leaves the host for a third-party API",
        weight=2.0,
    )
