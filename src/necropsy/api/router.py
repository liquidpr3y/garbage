"""The single APIRouter the host mounts.

Nothing here may assume it owns the application: no startup hooks, no global
middleware, no root-path routes, every path relative to the mount prefix. That
is what keeps the Phase 6 move from sidecar to in-process mount a config change
rather than a port. tests/test_mount.py enforces it.
"""

from __future__ import annotations

from fastapi import APIRouter

from necropsy.api import ws
from necropsy.api.routes import (
    actions, ai, analysis, attack, cases, findings, jobs, meta, samples, sandbox,
)

router = APIRouter()
router.include_router(cases.router)
router.include_router(samples.router)
router.include_router(jobs.router)
router.include_router(findings.router)
router.include_router(actions.router)
router.include_router(analysis.router)
router.include_router(sandbox.router)
router.include_router(attack.router)
router.include_router(ai.router)
router.include_router(meta.router)
router.include_router(ws.router)


@router.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    from necropsy import __version__

    return {"status": "ok", "module": "necropsy", "version": __version__}
