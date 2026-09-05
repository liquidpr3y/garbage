"""Job kind -> handler.

Kinds a later phase implements are listed here with the phase that lands them,
so accepting a proposal for unimplemented work fails with something an operator
can read rather than a KeyError.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from necropsy.enums import JobKind

Handler = Callable[..., dict[str, Any]]

NOT_YET_IMPLEMENTED: dict[JobKind, str] = {
    JobKind.AI_SUMMARISE: "Phase 5 (Claude API)",
}


class JobNotImplemented(RuntimeError):
    def __init__(self, kind: JobKind) -> None:
        self.kind = kind
        super().__init__(f"{kind.value} is not implemented until {NOT_YET_IMPLEMENTED[kind]}")


def handler_for(kind: JobKind) -> Handler:
    if kind in NOT_YET_IMPLEMENTED:
        raise JobNotImplemented(kind)

    # Imported lazily: handlers import repos and services, which import the
    # registry back for validation.
    if kind is JobKind.IDENTIFY:
        from necropsy.jobs.tasks.identify import run

        return run
    if kind is JobKind.HASH_PIVOT:
        from necropsy.jobs.tasks.hash_pivot import run

        return run
    if kind is JobKind.STATIC_TRIAGE:
        from necropsy.jobs.tasks.static_triage import run

        return run
    if kind is JobKind.YARA_SCAN:
        from necropsy.jobs.tasks.yara_scan import run

        return run
    if kind is JobKind.GHIDRA_DECOMPILE:
        from necropsy.jobs.tasks.ghidra_decompile import run

        return run
    if kind is JobKind.DETONATE:
        from necropsy.jobs.tasks.detonate import run

        return run
    if kind is JobKind.SIGMA_SWEEP:
        from necropsy.jobs.tasks.sigma_sweep import run

        return run
    raise KeyError(f"no handler registered for {kind}")


def is_implemented(kind: JobKind) -> bool:
    return kind not in NOT_YET_IMPLEMENTED
