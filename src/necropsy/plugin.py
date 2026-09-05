"""Module descriptor the pentest GUI backend discovers.

The host enumerates the ``pentestgui.modules`` entry point group at boot and
mounts whatever it finds. Adding Necropsy is then ``pip install -e ../necropsy``
plus a restart; removing it is ``pip uninstall``. See docs/HOST_INTEGRATION.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from necropsy.api.router import router as api_router
from necropsy.contracts.host import Capability, HostServices


@dataclass(frozen=True)
class ModuleDescriptor:
    slug: str
    title: str
    router: Any
    migration_head: str
    required_capabilities: set[str] = field(default_factory=set)

    def mount(self, app: Any, host: HostServices, prefix: str | None = None) -> str:
        """Attach our router to the host app and adopt its services."""
        missing = {c for c in self.required_capabilities if not host.has(c)}
        if missing:
            raise RuntimeError(f"host is missing required capabilities: {sorted(missing)}")

        from necropsy.runtime import set_host
        from necropsy.sinks import install_if_configured

        set_host(host)
        install_if_configured()
        mount_at = prefix or f"/api/v1/{self.slug}"
        app.include_router(self.router, prefix=mount_at)
        return mount_at

    def healthcheck(self) -> dict[str, Any]:
        from necropsy.db.session import get_engine
        from necropsy.intake.hashing import have_tlsh
        from necropsy.intake.identify import have_magic

        return {
            "module": self.slug,
            "database": get_engine().url.render_as_string(hide_password=True),
            "optional_tlsh": have_tlsh(),
            "optional_libmagic": have_magic(),
        }


MODULE = ModuleDescriptor(
    slug="necropsy",
    title="Malware Analysis",
    router=api_router,
    migration_head="0001_initial",
    # Nothing is required: the host may not have engagements or a shared risk
    # policy yet, and the module must still mount.
    required_capabilities=set(),
)

__all__ = ["MODULE", "Capability", "ModuleDescriptor"]
