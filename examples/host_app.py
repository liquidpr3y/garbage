"""A stand-in for the pentest GUI backend, to prove the mount seam works.

This is the ~40 lines the real backend needs to add. It discovers installed
modules through the `pentestgui.modules` entry point group, hands each one a
`HostServices` implementation, and mounts its router. Necropsy appears at
`/api/v1/necropsy` with no import of Necropsy anywhere in this file.

Run it:

    pip install -e .
    uvicorn examples.host_app:app --port 8000
    curl localhost:8000/api/v1/necropsy/meta/module

The point is what is absent: no `import necropsy`, no hardcoded route list, no
knowledge of what the module does. Uninstalling the package removes the panels.
"""

from __future__ import annotations

import importlib.metadata
import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI

log = logging.getLogger(__name__)

MODULE_GROUP = "pentestgui.modules"


class ExampleHostServices:
    """What the real pentest backend would supply.

    Only `redis`, `publish`, `actor` and `artifact_root` are required; the rest
    sit behind `has()` so a host that has not grown engagements yet still
    mounts every module cleanly.
    """

    def __init__(self, operator: str = "host-operator") -> None:
        self._operator = operator
        self._redis: Any = None

    def redis(self) -> Any:
        if self._redis is None:
            import redis as redis_lib

            self._redis = redis_lib.Redis.from_url("redis://localhost:6379/0")
        return self._redis

    def publish(self, channel: str, event: Any) -> None:
        try:
            self.redis().publish(channel, event.model_dump_json())
        except Exception as exc:  # noqa: BLE001
            log.debug("host event publish unavailable: %s", exc)

    def actor(self) -> str:
        return self._operator

    def artifact_root(self) -> Path:
        return Path("~/.pentestgui/artifacts").expanduser()

    def risk_policy(self) -> Any:
        from necropsy.contracts.host import RiskPolicy  # only for the type

        return RiskPolicy()

    def resolve_engagement(self, ref: str) -> dict[str, Any] | None:
        return None

    def has(self, capability: str) -> bool:
        return capability == "risk_policy"


def discover_and_mount(app: FastAPI, host: Any) -> list[dict[str, Any]]:
    """Mount every installed module. This is the whole integration."""
    mounted: list[dict[str, Any]] = []
    for entry_point in importlib.metadata.entry_points(group=MODULE_GROUP):
        try:
            module = entry_point.load()
            prefix = module.mount(app, host)
        except Exception as exc:  # noqa: BLE001 - one bad module must not stop the app
            log.error("module %s failed to mount: %s", entry_point.name, exc)
            mounted.append({"name": entry_point.name, "mounted": False, "error": str(exc)})
            continue
        mounted.append(
            {
                "name": module.slug,
                "title": module.title,
                "prefix": prefix,
                "mounted": True,
            }
        )
        log.info("mounted %s at %s", module.slug, prefix)
    return mounted


def create_app(host: Any | None = None) -> FastAPI:
    app = FastAPI(title="Pentest GUI backend (example host)")
    app.state.modules = discover_and_mount(app, host or ExampleHostServices())

    @app.get("/api/v1/modules")
    def modules() -> list[dict[str, Any]]:
        """What the shell calls at startup to build its navigation."""
        return app.state.modules

    return app


app = create_app()
