"""The detonation contract.

Written so that adding an x86 host later -- an Intel box on the bench, or a
cloud VM -- is one class implementing this interface, not a rewrite. The POC
runs ARM-only by decision (docs/ARCHITECTURE.md S5); this is the seam that
keeps that decision cheap to revisit.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any

from necropsy.enums import Arch


class TargetError(RuntimeError):
    """The target failed to do something it was asked to do."""


class NoTargetConfigured(TargetError):
    """No usable detonation target exists in this configuration."""


class GuestTimeout(TargetError):
    pass


class EgressUnavailable(TargetError):
    """Egress was requested but this install cannot actually provide it.

    Raised rather than silently detonating isolated: an operator who asked for
    live C2 contact and got a quiet run would read the silence as the sample
    doing nothing.
    """


class EmulationFidelity(str, Enum):
    """How much a behavioural verdict from this pairing is worth."""

    NATIVE = "native"
    INTERPRETED = "interpreted"
    EMULATED = "emulated"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class TargetCapabilities:
    name: str
    arch: Arch
    os: str
    has_sysmon: bool
    supports_egress: bool
    snapshot: str
    guest_workdir: str

    def fidelity_for(self, sample_arch: Arch, native_code: bool) -> EmulationFidelity:
        if not native_code:
            # Scripts, macros and managed code run through an interpreter or
            # runtime that is native on this host, so behaviour is faithful.
            return EmulationFidelity.INTERPRETED
        if sample_arch in (Arch.UNKNOWN, Arch.NOT_APPLICABLE):
            return EmulationFidelity.EMULATED
        if sample_arch == self.arch:
            return EmulationFidelity.NATIVE
        if self.arch is Arch.ARM64 and sample_arch in (Arch.X86, Arch.X86_64):
            return EmulationFidelity.EMULATED
        return EmulationFidelity.UNSUPPORTED


@dataclass
class ExecResult:
    exit_code: int | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    timed_out: bool = False
    detail: str = ""


@dataclass
class CollectedFile:
    name: str
    data: bytes
    kind: str


@dataclass
class TargetFingerprint:
    """Recorded on every detonation so a finding can be re-read in context.

    Six months later, "the sample did nothing" is only interpretable if you
    know what it ran on.
    """

    target: str
    arch: str
    os: str
    snapshot: str
    egress: bool
    fidelity: str
    tool_versions: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target, "arch": self.arch, "os": self.os,
            "snapshot": self.snapshot, "egress": self.egress,
            "fidelity": self.fidelity, "tool_versions": self.tool_versions,
        }


class DetonationTarget(ABC):
    """A machine that is not this one.

    Implementations must satisfy two rules:

    * `revert()` is safe to call at any point, including after a partial or
      failed `prepare()`. The detonate job calls it in a `finally`, and a dirty
      snapshot inherited by the next sample is worse than a failed run.
      inherited by the next sample is worse than a failed run.
    * No method may execute the sample anywhere but inside the guest.
    """

    caps: TargetCapabilities

    @classmethod
    @abstractmethod
    def from_settings(cls, settings: Any, *, egress: bool) -> DetonationTarget: ...

    @abstractmethod
    def prepare(self) -> None:
        """Revert to the clean snapshot and bring the guest up."""

    @abstractmethod
    def push(self, local: Path, guest_name: str) -> PurePosixPath:
        """Copy a file into the guest. Returns the path it landed at."""

    @abstractmethod
    def execute(self, guest_path: str, args: list[str], timeout_s: float) -> ExecResult:
        """Run the sample inside the guest."""

    @abstractmethod
    def collect(self) -> list[CollectedFile]:
        """Pull back whatever the guest produced (screenshots, logs)."""

    @abstractmethod
    def revert(self) -> None:
        """Power off and restore the clean snapshot. Must never raise."""

    @abstractmethod
    def fingerprint(self, *, sample_arch: Arch, native_code: bool) -> TargetFingerprint: ...

    @property
    def guest_hostname(self) -> str | None:
        """Hostname the guest reports to the SIEM, for telemetry correlation."""
        return None
