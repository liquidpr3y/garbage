"""Detonation targets.

Deliberately absent: any implementation that runs a sample on the host. See
`necropsy/sandbox/__init__.py`.
"""

from __future__ import annotations

from necropsy.config import get_settings
from necropsy.sandbox.targets.base import (
    DetonationTarget,
    ExecResult,
    NoTargetConfigured,
    TargetCapabilities,
    TargetError,
)

# Every target this build can construct. A name is only listed here if it
# executes on a separate machine.
REGISTRY: dict[str, str] = {
    "vmware": "necropsy.sandbox.targets.vmware:VMwareFusionTarget",
    "remote": "necropsy.sandbox.targets.remote:RemoteAgentTarget",
}


def build_target(*, egress: bool = False) -> DetonationTarget:
    """Construct the configured target, or explain precisely what is missing."""
    settings = get_settings()
    if not settings.sandbox_enabled:
        raise NoTargetConfigured(
            "Dynamic analysis is disabled. Set NECROPSY_SANDBOX_ENABLED=true and "
            "configure a target before detonating anything."
        )

    name = (settings.sandbox_target or "").strip().lower()
    if name not in REGISTRY:
        raise NoTargetConfigured(
            f"NECROPSY_SANDBOX_TARGET must be one of {sorted(REGISTRY)}; got {name!r}"
        )

    module_path, _, class_name = REGISTRY[name].partition(":")
    import importlib

    cls = getattr(importlib.import_module(module_path), class_name)
    return cls.from_settings(settings, egress=egress)


__all__ = [
    "DetonationTarget",
    "ExecResult",
    "NoTargetConfigured",
    "REGISTRY",
    "TargetCapabilities",
    "TargetError",
    "build_target",
]
