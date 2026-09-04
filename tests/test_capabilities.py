"""Capability detection, including the cases where it must stay quiet."""

from __future__ import annotations

from necropsy.analysis.capabilities import (
    CATALOGUE,
    CATALOGUE_BY_ID,
    detect,
    detection_quality,
)
from necropsy.enums import KillChainPhase, Severity


def _ids(hits) -> set[str]:  # type: ignore[no-untyped-def]
    return {h.capability.id for h in hits}


def test_injection_needs_the_full_sequence_not_one_api() -> None:
    """OpenProcess alone is ordinary. The sequence is what means something."""
    assert "process_injection" not in _ids(detect(["OpenProcess"], []))
    assert "process_injection" in _ids(
        detect(["OpenProcess", "VirtualAllocEx", "WriteProcessMemory"], [])
    )


def test_benign_import_set_produces_nothing() -> None:
    assert detect(["GetLastError", "CloseHandle", "Sleep", "malloc"], ["hello world"]) == []


def test_ansi_wide_suffixes_are_equivalent() -> None:
    wide = detect(["RegSetValueExW", "RegCreateKeyExW"], [r"software\microsoft\windows\currentversion\run"])
    ansi = detect(["RegSetValueExA", "RegCreateKeyExA"], [r"software\microsoft\windows\currentversion\run"])
    assert _ids(wide) == _ids(ansi) == {"registry_run_persistence"}


def test_string_only_capabilities_fire_without_imports() -> None:
    hits = detect([], ["vssadmin delete shadows", "win32_shadowcopy"])
    assert "shadow_copy_destruction" in _ids(hits)


def test_confidence_rises_with_more_indicators() -> None:
    few = detect(["OpenProcess", "VirtualAllocEx", "WriteProcessMemory"], [])
    many = detect(
        ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
         "NtWriteVirtualMemory", "QueueUserAPC"], [],
    )
    assert next(h for h in many if h.capability.id == "process_injection").confidence > next(
        h for h in few if h.capability.id == "process_injection"
    ).confidence


def test_confidence_never_reaches_certainty() -> None:
    """Static capability detection is defeasible; the number must say so."""
    hits = detect(sorted({fn for c in CATALOGUE for fn in c.imports}), [])
    assert all(h.confidence <= 0.9 for h in hits)


def test_results_are_ordered_by_severity() -> None:
    hits = detect(
        ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
         "GetComputerNameA", "GetUserNameA", "GetSystemInfo"],
        ["vssadmin delete shadows", "win32_shadowcopy"],
    )
    order = [h.capability.severity for h in hits]
    ranking = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
               Severity.HIGH: 3, Severity.CRITICAL: 4}
    assert [ranking[s] for s in order] == sorted((ranking[s] for s in order), reverse=True)


def test_every_capability_carries_an_attack_mapping() -> None:
    for capability in CATALOGUE:
        assert capability.attack, f"{capability.id} has no ATT&CK technique"
        assert all(t.startswith("T1") for t in capability.attack), capability.id
        assert isinstance(capability.kill_chain_phase, KillChainPhase)


def test_catalogue_ids_are_unique() -> None:
    assert len(CATALOGUE_BY_ID) == len(CATALOGUE)


def test_packed_sample_reports_degraded_coverage() -> None:
    quality = detection_quality(import_count=4, string_count=12, packed=True)
    assert quality["degraded"] is True
    assert "not evidence" in quality["note"]


def test_healthy_sample_reports_good_coverage() -> None:
    quality = detection_quality(import_count=200, string_count=3000, packed=False)
    assert quality["degraded"] is False
