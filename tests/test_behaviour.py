"""Behavioural analysis of Sysmon telemetry, and the verdict on readability."""

from __future__ import annotations

from typing import Any

from necropsy.enums import Severity
from necropsy.sandbox.behaviour import DORMANCY_EVENT_THRESHOLD, analyse
from necropsy.sandbox.targets.base import EmulationFidelity


def process(name: str, parent: str = "explorer.exe", cmdline: str = "") -> dict[str, Any]:
    return {
        "event": {"code": "1"},
        "process": {"name": name, "parent": {"name": parent}, "command_line": cmdline or name},
    }


BUSY = [
    process("loader.exe"),
    process("powershell.exe", "loader.exe", "powershell -nop -w hidden -enc SQBFAFgA"),
    process("vssadmin.exe", "loader.exe", "vssadmin delete shadows /all /quiet"),
    process("cmd.exe", "loader.exe", "cmd /c netsh advfirewall set allprofiles state off"),
    {"event": {"code": "13"}, "registry": {"path": r"HKU\S-1-5\Software\Microsoft\Windows\CurrentVersion\Run\upd"}},
    {"event": {"code": "3"}, "destination": {"ip": "185.220.101.44", "port": 443}},
    {"event": {"code": "22"}, "dns": {"question": {"name": "gate.evil-c2.ru"}}},
    {"event": {"code": "8"}},
    {"event": {"code": "11"}, "file": {"path": r"C:\Users\a\AppData\Roaming\svc.exe"}},
]


def _ids(report) -> set[str]:  # type: ignore[no-untyped-def]
    return {b.id for b in report.behaviours}


def test_identifies_the_obvious_behaviours() -> None:
    report = analyse(BUSY, fidelity=EmulationFidelity.NATIVE)
    assert {
        "autorun_persistence", "remote_thread_injection", "recovery_destruction",
        "defence_tampering", "network_activity", "staging_writes",
    } <= _ids(report)


def test_behavioural_confidence_exceeds_static_capability_confidence() -> None:
    """Doing a thing is a stronger claim than being able to do it."""
    report = analyse(BUSY, fidelity=EmulationFidelity.NATIVE)
    autorun = next(b for b in report.behaviours if b.id == "autorun_persistence")
    assert autorun.confidence >= 0.9
    assert autorun.attack == ["T1547.001"]
    assert autorun.severity is Severity.HIGH


def test_private_addresses_are_not_reported_as_c2() -> None:
    events = BUSY + [{"event": {"code": "3"}, "destination": {"ip": "10.0.0.1"}}]
    report = analyse(events, fidelity=EmulationFidelity.NATIVE)
    network = next(b for b in report.behaviours if b.id == "network_activity")
    assert "10.0.0.1" not in network.evidence["ips"]
    assert "185.220.101.44" in network.evidence["ips"]


def test_flattened_ecs_documents_are_handled() -> None:
    """Some pipelines deliver dotted keys rather than nested objects."""
    flat = [
        {"event.code": "13", "registry.path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x"},
        {"event.code": "8"},
    ] + BUSY[:7]
    report = analyse(flat, fidelity=EmulationFidelity.NATIVE)
    assert "autorun_persistence" in _ids(report)


def test_process_tree_is_built() -> None:
    report = analyse(BUSY, fidelity=EmulationFidelity.NATIVE)
    tree = {entry["parent"]: entry["children"] for entry in report.process_tree}
    assert "powershell.exe" in tree["loader.exe"]


def test_a_busy_run_is_readable() -> None:
    report = analyse(BUSY, fidelity=EmulationFidelity.NATIVE)
    assert report.readable is True


def test_a_quiet_emulated_run_is_inconclusive_not_clean() -> None:
    """The single most important judgement in the dynamic pipeline."""
    report = analyse(BUSY[:2], fidelity=EmulationFidelity.EMULATED)
    assert report.readable is False
    assert "INCONCLUSIVE" in report.verdict_note
    assert "emulation" in report.verdict_note
    assert "benign" in report.verdict_note


def test_a_quiet_native_run_suggests_the_other_explanations() -> None:
    report = analyse(BUSY[:2], fidelity=EmulationFidelity.NATIVE)
    assert report.readable is False
    assert "detected the sandbox" in report.verdict_note
    assert "trigger" in report.verdict_note


def test_an_unsupported_pairing_says_nothing_was_tested() -> None:
    report = analyse([], fidelity=EmulationFidelity.UNSUPPORTED)
    assert report.readable is False
    assert "Nothing about the sample's behaviour was tested" in report.verdict_note


def test_a_busy_run_with_no_known_behaviour_is_still_readable() -> None:
    """Readable and quiet are different claims; only one is about the sample."""
    benign = [process(f"svchost{i}.exe") for i in range(DORMANCY_EVENT_THRESHOLD + 2)]
    report = analyse(benign, fidelity=EmulationFidelity.NATIVE)
    assert report.readable is True
    assert "no known-malicious behaviour matched" in report.verdict_note
    assert "may be waiting on a trigger" in report.verdict_note
