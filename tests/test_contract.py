"""The GUI contract, and the mount seam that delivers it.

Phase 6 is the merge into the single-pane shell, so the failure to guard
against is a backend change that passes every backend test and silently breaks
the panel. Two checks: the route/field surface is committed and diffed, and
timestamps stay unambiguous.
"""

from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from necropsy.contract import diff, surface_for_module

REPO = Path(__file__).resolve().parents[1]
COMMITTED = REPO / "contract" / "surface.json"


def test_the_committed_contract_matches_the_code() -> None:
    """A removed route or renamed field must fail here, not in Xcode."""
    assert COMMITTED.exists(), "run `necropsy contract --bless`"
    problems = diff(surface_for_module(), json.loads(COMMITTED.read_text()))
    breaking = [p for p in problems if not p.startswith("added route")]
    assert not breaking, (
        "breaking GUI contract changes:\n  "
        + "\n  ".join(breaking)
        + "\n\nIf intended, re-bless with `necropsy contract --bless`."
    )


def test_new_routes_are_reported_but_not_breaking() -> None:
    surface = surface_for_module()
    trimmed = {
        "surface_version": surface["surface_version"],
        "routes": {k: v for k, v in list(surface["routes"].items())[:-1]},
    }
    problems = diff(surface, trimmed)
    assert problems and all(p.startswith("added route") for p in problems)


def test_removing_a_field_is_detected() -> None:
    surface = surface_for_module()
    route = "GET /cases/{case_id}"
    mutated = json.loads(json.dumps(surface))
    mutated["routes"][route]["response_fields"].append("a_field_that_went_away")

    problems = diff(surface, mutated)
    assert any("REMOVED field" in p and route in p for p in problems)


def test_every_panel_route_is_in_the_contract() -> None:
    """Whatever the module advertises, the panel must be able to call."""
    from necropsy.api.routes.meta import _panels

    routes = surface_for_module()["routes"]
    templates = {r.split(" ", 1)[1] for r in routes}
    for panel in _panels():
        assert panel.path in templates, f"panel {panel.id} points at an unrouted path"


# -- timestamps --------------------------------------------------------------


@pytest.fixture
def client(database, host):  # type: ignore[no-untyped-def]
    from necropsy.api.router import router

    app = FastAPI()
    app.include_router(router, prefix="/api/v1/necropsy")
    with TestClient(app) as c:
        yield c


def test_orm_returns_timezone_aware_datetimes(session, host) -> None:  # type: ignore[no-untyped-def]
    """SQLite drops tzinfo; the type decorator has to put it back.

    A naive timestamp on the wire is ambiguous for every consumer, and a
    browser reads it as local time -- silently wrong by up to twelve hours on
    a case timeline.
    """
    from necropsy.cases import service as case_service
    from necropsy.db.repos import cases as cases_repo

    created = case_service.create_case(session, host, name="TZ")
    session.commit()
    session.expire_all()

    reloaded = cases_repo.get(session, created.id)
    assert reloaded.created_at.tzinfo is not None
    assert reloaded.created_at.utcoffset() == timezone.utc.utcoffset(None)


def test_api_timestamps_carry_an_offset(client: TestClient) -> None:
    case = client.post("/api/v1/necropsy/cases", json={"name": "TZ"}).json()
    for field in ("created_at", "updated_at"):
        value = case[field]
        assert value.endswith("Z") or "+" in value[10:], (
            f"{field} has no timezone: {value!r} -- every client would have to guess"
        )
