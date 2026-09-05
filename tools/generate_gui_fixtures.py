#!/usr/bin/env python3
"""Capture real API responses as fixtures for the Swift client's tests.

The GUI contract spans two languages, so the strongest check available is to
decode responses the Python API actually produced with the Swift models that
will consume them. A field rename on either side then fails a test instead of
surfacing as an empty pane on someone's Mac.

Run: python tools/generate_gui_fixtures.py gui/Fixtures
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))


def main(out_dir: Path) -> int:
    tmp = tempfile.mkdtemp(prefix="necropsy-fixtures-")
    os.environ.update(
        NECROPSY_DB_URL=f"sqlite:///{tmp}/n.db",
        NECROPSY_VAULT_ROOT=f"{tmp}/vault",
        NECROPSY_VAULT_KEY=base64.b64encode(os.urandom(32)).decode(),
        NECROPSY_JOB_RUNNER="inline",
        NECROPSY_OPERATOR="fixture.generator",
        NECROPSY_TARGET_ARCHES="arm64",
        NECROPSY_ELASTIC_SETTLE_SECONDS="0",
    )

    from necropsy.config import get_settings

    get_settings.cache_clear()
    from necropsy.db.session import configure, create_all, make_engine

    engine = make_engine(get_settings().db_url)
    configure(engine)
    create_all(engine)

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from necropsy.api.router import router

    app = FastAPI()
    app.include_router(router, prefix="/api/v1/necropsy")
    client = TestClient(app)
    prefix = "/api/v1/necropsy"
    confirm = {"X-Necropsy-Confirm-Malware": "true"}

    from conftest import loader_spec
    from pebuilder import build

    sample_path = build(Path(tmp) / "loader.exe", loader_spec())

    case = client.post(
        f"{prefix}/cases", json={"name": "Fixture case", "severity": "medium", "tags": ["fixture"]}
    ).json()
    ingest = client.post(
        f"{prefix}/cases/{case['id']}/samples",
        files={"file": ("loader.exe", sample_path.read_bytes())},
        headers=confirm,
    ).json()
    sha = ingest["sample"]["sha256"]

    actions = client.get(f"{prefix}/cases/{case['id']}/actions").json()
    triage = next(a for a in actions if a["kind"] == "static_triage")
    client.post(f"{prefix}/actions/{triage['id']}/accept")

    captures = {
        "module": f"{prefix}/meta/module",
        "case_list": f"{prefix}/cases",
        "case_detail": f"{prefix}/cases/{case['id']}",
        "timeline": f"{prefix}/cases/{case['id']}/timeline",
        "case_samples": f"{prefix}/cases/{case['id']}/samples",
        "sample_detail": f"{prefix}/samples/{sha}",
        "findings": f"{prefix}/cases/{case['id']}/findings",
        "actions": f"{prefix}/cases/{case['id']}/actions",
        "static_report": f"{prefix}/samples/{sha}/static",
        "strings": f"{prefix}/samples/{sha}/strings?limit=25",
        "functions": f"{prefix}/samples/{sha}/functions",
        "function_stats": f"{prefix}/samples/{sha}/function-stats",
        "attack": f"{prefix}/cases/{case['id']}/attack",
        "attack_tactics": f"{prefix}/attack/tactics",
        "detonations": f"{prefix}/cases/{case['id']}/detonations",
        "sandbox_status": f"{prefix}/sandbox/status",
        "tooling": f"{prefix}/analysis/tooling",
        "ai_status": f"{prefix}/ai/status",
        "attack_status": f"{prefix}/attack/status",
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for name, path in captures.items():
        response = client.get(path)
        if response.status_code != 200:
            print(f"  skip {name}: HTTP {response.status_code}")
            continue
        (out_dir / f"{name}.json").write_text(
            json.dumps(response.json(), indent=2, sort_keys=True) + "\n"
        )
        written += 1

    # Placeholders are not captured from a live run, so build them from the
    # models directly -- the panel still has to decode them.
    _static_fixtures(out_dir)

    print(f"wrote {written} live fixtures to {out_dir}")
    return 0


def _static_fixtures(out_dir: Path) -> None:
    """Shapes that need a lab or credentials to occur naturally."""
    from necropsy.contracts.events import Event, EventType

    (out_dir / "event_finding.json").write_text(
        Event(
            type=EventType.FINDING_CREATED,
            case_id="00000000-0000-0000-0000-000000000001",
            payload={
                "job_id": "job-1", "finding_id": "finding-1",
                "title": "Wrote an autorun registry value",
                "severity": "high", "type": "behaviour:autorun_persistence",
            },
        ).model_dump_json(indent=2)
        + "\n"
    )
    (out_dir / "event_action.json").write_text(
        Event(
            type=EventType.ACTION_PROPOSED,
            case_id="00000000-0000-0000-0000-000000000001",
            payload={
                "action_id": "action-1", "kind": "detonate",
                "title": "Detonate in sandbox (isolated)",
                "risk_score": 7.2, "risk_band": "high", "available": False,
            },
        ).model_dump_json(indent=2)
        + "\n"
    )


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "gui" / "Fixtures"
    raise SystemExit(main(target))
