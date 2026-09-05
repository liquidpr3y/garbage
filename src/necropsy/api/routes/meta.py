"""What the host shell needs to render Necropsy as part of one product.

The pentest GUI owns the window, the navigation and the design language. It
cannot hardcode Necropsy's panels without becoming coupled to this module's
release cycle, so the module describes itself: which panels exist, what each
binds to, and which are usable on this install.

`enabled` is computed from the same tooling probes `necropsy doctor` uses. A
panel whose backing tool is missing is shown disabled with the reason, rather
than appearing to work and failing on click.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from necropsy import __version__
from necropsy.schemas.meta import ModuleDescriptorOut, PanelDescriptor

router = APIRouter(tags=["meta"])


def _panels() -> list[PanelDescriptor]:
    from necropsy.ai.client import credential_source, have_sdk
    from necropsy.analysis.ghidra import have_ghidra
    from necropsy.attack.sigma import have_sigma
    from necropsy.elastic.client import ElasticClient
    from necropsy.sandbox.targets import NoTargetConfigured, build_target

    def sandbox_state() -> tuple[bool, str | None]:
        try:
            build_target()
            return True, None
        except NoTargetConfigured as exc:
            return False, str(exc)
        except Exception as exc:  # noqa: BLE001
            return False, f"{type(exc).__name__}: {exc}"

    sandbox_ready, sandbox_reason = sandbox_state()
    ai_source = credential_source() if have_sdk() else None
    elastic = ElasticClient.try_from_settings()

    return [
        PanelDescriptor(
            id="cases",
            title="Cases",
            icon="folder",
            path="/cases",
            stream="/ws/cases/{case_id}",
            description="Case list and merged timeline of everything that happened.",
            enabled=True,
        ),
        PanelDescriptor(
            id="sample",
            title="Sample",
            icon="doc.text.magnifyingglass",
            path="/samples/{sha256}/static",
            description="PE structure, strings and IOCs, capability detection, YARA hits.",
            enabled=True,
        ),
        PanelDescriptor(
            id="decompile",
            title="Decompilation",
            icon="chevron.left.forwardslash.chevron.right",
            path="/samples/{sha256}/functions",
            description="Recovered functions and decompiled C, searchable.",
            enabled=have_ghidra(),
            disabled_reason=None if have_ghidra() else "Ghidra not installed on this host",
        ),
        PanelDescriptor(
            id="sandbox",
            title="Sandbox",
            icon="play.rectangle",
            path="/cases/{case_id}/detonations",
            description="Detonation timeline, telemetry and the readability verdict.",
            enabled=sandbox_ready,
            disabled_reason=sandbox_reason,
        ),
        PanelDescriptor(
            id="attack",
            title="ATT&CK",
            icon="square.grid.3x3",
            path="/cases/{case_id}/attack",
            description="Technique heatmap, evidence grades and detection gaps.",
            enabled=True,
        ),
        PanelDescriptor(
            id="report",
            title="AI Report",
            icon="sparkles",
            path="/cases/{case_id}/report",
            description="Model-written case report and drafted detection rules.",
            enabled=ai_source is not None,
            disabled_reason=(
                None if ai_source else "no Anthropic credentials on this host"
            ),
        ),
    ]


@router.get("/meta/module", response_model=ModuleDescriptorOut)
def module_descriptor() -> Any:
    """Self-description for the host shell's navigation."""
    from necropsy.plugin import MODULE

    return ModuleDescriptorOut(
        slug=MODULE.slug,
        title=MODULE.title,
        version=__version__,
        migration_head=MODULE.migration_head,
        # The GUI reuses the host's design tokens; risk bands are the one piece
        # of shared vocabulary it needs from us to colour both modules alike.
        risk_bands=["minimal", "low", "moderate", "high", "severe"],
        panels=_panels(),
    )


@router.get("/meta/health")
def health() -> dict[str, Any]:
    """Deep health: is this install actually able to do the work it offers?"""
    from necropsy.db.session import get_engine

    panels = _panels()
    return {
        "status": "ok",
        "module": "necropsy",
        "version": __version__,
        "database": get_engine().url.render_as_string(hide_password=True),
        "panels_enabled": [p.id for p in panels if p.enabled],
        "panels_disabled": {p.id: p.disabled_reason for p in panels if not p.enabled},
    }
