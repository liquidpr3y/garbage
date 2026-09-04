"""What Necropsy needs from whatever is hosting it.

Only ``redis``, ``publish``, ``actor`` and ``artifact_root`` are ever required.
Everything else sits behind a ``has()`` capability check and must degrade, so a
host backend that has not grown engagements or a shared risk policy yet still
mounts the module cleanly.

``StandaloneHost`` (necropsy.standalone.host) implements all of it locally.
While the pentest backend is an early prototype that is the deployment mode we
actually run in -- see docs/HOST_INTEGRATION.md S1.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from necropsy.contracts.events import Event


class RiskPolicy(BaseModel):
    """Host-wide thresholds so both modules colour risk identically."""

    auto_execute_max: float = Field(
        default=-1.0,
        description=(
            "Proposals at or below this score may execute without a human. "
            "Negative disables it entirely, which is the Necropsy default and "
            "the only setting under which the SAFETY.md invariants hold."
        ),
    )
    warn_above: float = 6.5
    require_confirmation_above: float = 4.0


class Capability:
    """Capability names passed to ``HostServices.has``."""

    ENGAGEMENTS = "engagements"
    RISK_POLICY = "risk_policy"
    IDENTITY = "identity"


@runtime_checkable
class HostServices(Protocol):
    def redis(self) -> Any:
        """A redis-py compatible client. Typed loosely to keep redis out of contracts."""

    def publish(self, channel: str, event: Event) -> None: ...

    def actor(self) -> str:
        """Operator identity recorded on audit rows and action decisions."""

    def artifact_root(self) -> Path: ...

    def risk_policy(self) -> RiskPolicy: ...

    def resolve_engagement(self, ref: str) -> dict[str, Any] | None: ...

    def has(self, capability: str) -> bool: ...
