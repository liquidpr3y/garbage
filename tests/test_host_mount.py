"""The reference host app: proof the mount seam is real.

`examples/host_app.py` is the ~40 lines the pentest backend needs to add. It
discovers modules through the `pentestgui.modules` entry point and mounts them
without importing Necropsy at all. If that stops working, the Phase 6 merge
stops being a config change and becomes a port.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def host_client(database, host):  # type: ignore[no-untyped-def]
    from examples.host_app import create_app

    with TestClient(create_app(host)) as client:
        yield client


def test_the_host_discovers_necropsy_without_importing_it(host_client: TestClient) -> None:
    modules = host_client.get("/api/v1/modules").json()
    assert len(modules) == 1
    assert modules[0] == {
        "name": "necropsy",
        "title": "Malware Analysis",
        "prefix": "/api/v1/necropsy",
        "mounted": True,
    }


def test_the_example_host_file_never_imports_necropsy_at_module_scope() -> None:
    """The point of the entry point is that the host stays uncoupled."""
    import ast

    source = (Path(__file__).resolve().parents[1] / "examples" / "host_app.py").read_text()
    tree = ast.parse(source)
    for node in tree.body:  # module scope only; a type-only import inside a function is fine
        if isinstance(node, ast.Import):
            assert not any(a.name.startswith("necropsy") for a in node.names)
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("necropsy")


def test_the_mounted_module_serves_its_whole_surface(host_client: TestClient) -> None:
    assert host_client.get("/api/v1/necropsy/meta/health").json()["status"] == "ok"
    assert host_client.get("/api/v1/necropsy/cases").status_code == 200
    assert host_client.get("/api/v1/necropsy/attack/status").status_code == 200


def test_the_module_describes_its_own_panels(host_client: TestClient) -> None:
    descriptor = host_client.get("/api/v1/necropsy/meta/module").json()
    assert descriptor["slug"] == "necropsy"
    assert {p["id"] for p in descriptor["panels"]} >= {
        "cases", "sample", "decompile", "sandbox", "attack", "report"
    }
    # Shared vocabulary, so one component colours both modules alike.
    assert descriptor["risk_bands"] == ["minimal", "low", "moderate", "high", "severe"]


def test_a_panel_that_cannot_work_here_says_why(host_client: TestClient) -> None:
    """Disabled with a reason beats available and failing on click."""
    panels = host_client.get("/api/v1/necropsy/meta/module").json()["panels"]
    disabled = [p for p in panels if not p["enabled"]]
    assert disabled, "no sandbox/Ghidra/credentials in CI, so some panels must be disabled"
    for panel in disabled:
        assert panel["disabled_reason"]


def test_deep_health_reports_what_is_usable(host_client: TestClient) -> None:
    health = host_client.get("/api/v1/necropsy/meta/health").json()
    assert "cases" in health["panels_enabled"]
    assert health["panels_disabled"]
    assert all(reason for reason in health["panels_disabled"].values())
