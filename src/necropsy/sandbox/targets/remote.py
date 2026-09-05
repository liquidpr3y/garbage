"""Remote x86 detonation host -- the seam, not yet the implementation.

The POC runs ARM-only by decision, so native x86 samples execute under
emulation or not at all. This class exists so that adding an Intel box or a
cloud VM later is one implementation against an interface the rest of the
platform already speaks, rather than a change to the detonate job, the
proposals, the findings or the schema.

It is deliberately a hard failure rather than a silent fallback to VMware: an
operator who selected a remote x86 host and quietly got an ARM guest would
draw exactly the wrong conclusion from a dormant run.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from necropsy.enums import Arch
from necropsy.sandbox.targets.base import (
    CollectedFile,
    DetonationTarget,
    ExecResult,
    NoTargetConfigured,
    TargetCapabilities,
    TargetFingerprint,
)

NOT_BUILT = (
    "The remote x86 detonation target is not implemented. The POC is ARM-only by "
    "decision (docs/ARCHITECTURE.md S5). This class holds the interface so an Intel "
    "host or cloud VM can be added without changing anything above it."
)


class RemoteAgentTarget(DetonationTarget):
    def __init__(self, *, arch: Arch = Arch.X86_64) -> None:
        self.caps = TargetCapabilities(
            name="remote-agent", arch=arch, os="windows", has_sysmon=True,
            supports_egress=False, snapshot="", guest_workdir="",
        )

    @classmethod
    def from_settings(cls, settings: Any, *, egress: bool = False) -> RemoteAgentTarget:
        raise NoTargetConfigured(NOT_BUILT)

    def prepare(self) -> None:
        raise NoTargetConfigured(NOT_BUILT)

    def push(self, local: Path, guest_name: str) -> PurePosixPath:
        raise NoTargetConfigured(NOT_BUILT)

    def execute(self, guest_path: str, args: list[str], timeout_s: float) -> ExecResult:
        raise NoTargetConfigured(NOT_BUILT)

    def collect(self) -> list[CollectedFile]:
        return []

    def revert(self) -> None:
        return None

    def fingerprint(self, *, sample_arch: Arch, native_code: bool) -> TargetFingerprint:
        return TargetFingerprint(
            target=self.caps.name, arch=self.caps.arch.value, os=self.caps.os,
            snapshot="", egress=False,
            fidelity=self.caps.fidelity_for(sample_arch, native_code).value,
        )
