"""The seam that keeps 'sidecar now, mounted later' from becoming a rewrite.

While the pentest backend is an early prototype we run standalone, so nothing
would otherwise exercise the mount path -- and the constraints it depends on
(no startup hooks, no global middleware, no root-path routes, every path
relative to the prefix) are exactly the sort that rot silently.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from necropsy.contracts.host import HostServices
from necropsy.plugin import MODULE


def test_module_descriptor_shape() -> None:
    assert MODULE.slug == "necropsy"
    assert MODULE.migration_head == "0001_initial"
    assert MODULE.required_capabilities == set(), (
        "the module must mount into a host that has grown no capabilities yet"
    )


def test_fake_host_satisfies_the_contract(host) -> None:  # type: ignore[no-untyped-def]
    assert isinstance(host, HostServices)


def test_mounts_into_a_bare_app_under_a_non_default_prefix(database, host, pe_sample: Path):  # type: ignore[no-untyped-def]
    app = FastAPI()
    mounted_at = MODULE.mount(app, host, prefix="/some/other/place")
    assert mounted_at == "/some/other/place"

    client = TestClient(app)
    assert client.get("/some/other/place/health").json()["module"] == "necropsy"

    case = client.post("/some/other/place/cases", json={"name": "Mounted"}).json()
    response = client.post(
        f"/some/other/place/cases/{case['id']}/samples",
        files={"file": ("invoice.exe", pe_sample.read_bytes())},
        headers={"X-Necropsy-Confirm-Malware": "true"},
    )
    assert response.status_code == 201, response.text


def test_mount_adopts_the_host_services(database, host) -> None:  # type: ignore[no-untyped-def]
    from necropsy.runtime import get_host

    MODULE.mount(FastAPI(), host)
    assert get_host() is host


def test_every_route_lives_under_the_mount_prefix(database, host) -> None:  # type: ignore[no-untyped-def]
    """Nothing may escape the prefix, or two mounted modules collide.

    Checked against a mounted app rather than the bare router: FastAPI defers
    sub-router expansion, so the router's own .routes are placeholders.
    """
    bare = set(_paths(FastAPI()))
    app = FastAPI()
    MODULE.mount(app, host, prefix="/mnt/necropsy")

    for path in set(_paths(app)) - bare:
        assert path.startswith("/mnt/necropsy/"), f"{path} escapes the mount prefix"
        assert path not in ("/", "/docs", "/openapi.json")


def _paths(app: FastAPI) -> list[str]:
    return [p for p in (getattr(r, "path", None) for r in app.routes) if p]


def test_router_registers_no_startup_hooks_or_middleware() -> None:
    router = MODULE.router
    assert not getattr(router, "on_startup", []), "startup hooks belong to the host app"
    assert not getattr(router, "on_shutdown", [])


def test_mount_refuses_a_host_missing_a_required_capability(host) -> None:  # type: ignore[no-untyped-def]
    from necropsy.plugin import ModuleDescriptor

    strict = ModuleDescriptor(
        slug="x", title="X", router=MODULE.router, migration_head="0001_initial",
        required_capabilities={"engagements"},
    )
    with pytest.raises(RuntimeError, match="engagements"):
        strict.mount(FastAPI(), host)


def test_contracts_do_not_import_the_rest_of_necropsy() -> None:
    """contracts/ must stay depend-able by the host without dragging us along."""
    import ast

    root = Path(__file__).resolve().parents[1] / "src" / "necropsy" / "contracts"
    banned = {"sqlalchemy", "rq", "redis", "fastapi", "lief", "tlsh", "alembic", "typer"}
    for module in root.glob("*.py"):
        tree = ast.parse(module.read_text())
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                top = name.split(".")[0]
                assert top not in banned, f"{module.name} imports {name}"
                if top == "necropsy":
                    assert name.startswith("necropsy.contracts"), (
                        f"{module.name} reaches outside contracts: {name}"
                    )
