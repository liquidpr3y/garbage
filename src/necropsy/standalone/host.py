"""HostServices for running without the pentest GUI backend.

While that backend is an early prototype this is the deployment mode we
actually run in, not a test double -- see docs/HOST_INTEGRATION.md S1. It has
to be genuinely usable, not just importable.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from necropsy.config import get_settings
from necropsy.contracts.events import Event
from necropsy.contracts.host import Capability, RiskPolicy

log = logging.getLogger(__name__)


class StandaloneHost:
    """Local implementations of everything the host would otherwise provide."""

    def __init__(self, redis_client: Any | None = None) -> None:
        self._redis = redis_client
        self._settings = get_settings()
        self._publish_warned = False

    def redis(self) -> Any:
        if self._redis is None:
            import redis as redis_lib

            self._redis = redis_lib.Redis.from_url(self._settings.redis_url)
        return self._redis

    def publish(self, channel: str, event: Event) -> None:
        # Event delivery is a UI nicety. Losing it must never fail the analysis
        # that produced it, so a dead broker degrades to a log line -- once.
        # A triage pass emits dozens of events, and repeating the same warning
        # per event buries the analysis output the operator came for.
        try:
            self.redis().publish(channel, event.model_dump_json())
        except Exception as exc:  # noqa: BLE001
            if not self._publish_warned:
                self._publish_warned = True
                log.warning(
                    "event publishing is unavailable (%s); the live case stream will be "
                    "empty for this process. Analysis is unaffected.", exc,
                )
            else:
                log.debug("event publish failed on %s: %s", channel, exc)

    def actor(self) -> str:
        return self._settings.operator

    def artifact_root(self) -> Path:
        return self._settings.vault_root

    def risk_policy(self) -> RiskPolicy:
        # auto_execute_max stays negative: nothing runs without a human, which
        # is the only setting under which the SAFETY.md invariants hold.
        return RiskPolicy()

    def resolve_engagement(self, ref: str) -> dict[str, Any] | None:  # noqa: ARG002
        return None

    def has(self, capability: str) -> bool:
        return capability in {Capability.RISK_POLICY}
