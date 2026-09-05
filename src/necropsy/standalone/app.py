"""The app we actually run while the pentest backend is an early prototype.

Same router, same code path as the eventual in-process mount -- only the
HostServices implementation and the fact that we own the FastAPI instance
differ. See docs/HOST_INTEGRATION.md S1.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from necropsy import __version__
from necropsy.api.router import router as api_router
from necropsy.runtime import set_host
from necropsy.standalone.host import StandaloneHost

log = logging.getLogger(__name__)

API_PREFIX = "/api/v1/necropsy"


def create_app(host: Any | None = None, *, create_schema: bool = False) -> FastAPI:
    set_host(host or StandaloneHost())

    app = FastAPI(
        title="Necropsy",
        version=__version__,
        description=(
            "Malware analysis and reverse engineering module. Runs standalone while the "
            "pentest GUI backend matures; the same router mounts in-process later."
        ),
    )
    # The macOS GUI is a native client, not a browser origin, but a local dev
    # front end is convenient. Loopback only.
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$",
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if create_schema:
        from necropsy.db.session import create_all

        create_all()

    # Mirror findings into Elastic when the lab's cluster is configured.
    from necropsy.sinks import install_if_configured

    log.info("finding sink: %s", install_if_configured())

    app.include_router(api_router, prefix=API_PREFIX)
    return app


app = create_app()
