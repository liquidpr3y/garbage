"""Process-wide handles.

RQ serialises job arguments, so a worker cannot be handed a live HostServices
object. Instead each process establishes its host once at boot (API app, CLI,
worker bootstrap) and tasks resolve it here.
"""

from __future__ import annotations

from necropsy.contracts.host import HostServices

_host: HostServices | None = None


def set_host(host: HostServices) -> None:
    global _host
    _host = host


def get_host() -> HostServices:
    global _host
    if _host is None:
        from necropsy.standalone.host import StandaloneHost

        _host = StandaloneHost()
    return _host


def reset_host() -> None:
    global _host
    _host = None
