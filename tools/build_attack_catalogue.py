#!/usr/bin/env python3
"""Reduce MITRE's enterprise-attack STIX bundle to the catalogue Necropsy ships.

Usage:
    python tools/build_attack_catalogue.py <enterprise-attack.json> <out.json>

Keeps only what the platform uses -- technique identity, tactics, sub-technique
parents, platforms, revocation mappings, and the log sources / Sysmon event
codes MITRE associates with detecting each technique. The full bundle is ~54MB;
the result is under 200KB, small enough to commit and to load at import time.

See src/necropsy/attack/data/ATTRIBUTION.md for the terms this data is used under.
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path


def external_id(obj: dict) -> str | None:
    ref = next(
        (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
        None,
    )
    return ref.get("external_id") if ref else None


def build(bundle: dict) -> dict:
    objects = bundle["objects"]
    by_id = {o["id"]: o for o in objects}

    version = next(
        (o.get("x_mitre_version") for o in objects if o.get("type") == "x-mitre-collection"),
        "unknown",
    )

    tactics = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tactics[obj["x_mitre_shortname"]] = {
            "id": external_id(obj), "name": obj["name"]
        }

    order: list[str] = []
    for obj in objects:
        if obj.get("type") == "x-mitre-matrix" and "Enterprise" in obj.get("name", ""):
            for ref in obj.get("tactic_refs", []):
                tactic = by_id.get(ref)
                if tactic and tactic.get("x_mitre_shortname"):
                    order.append(tactic["x_mitre_shortname"])
            break

    technique_ids = {
        o["id"]: external_id(o) for o in objects if o.get("type") == "attack-pattern"
    }

    # v19 chain: attack-pattern <- detects <- detection-strategy -> analytic -> log sources
    logs: dict[str, set[str]] = defaultdict(set)
    codes: dict[str, set[str]] = defaultdict(set)
    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "detects":
            continue
        tid = technique_ids.get(rel["target_ref"])
        strategy = by_id.get(rel["source_ref"])
        if not tid or not strategy:
            continue
        for ref in strategy.get("x_mitre_analytic_refs", []):
            analytic = by_id.get(ref)
            if not analytic:
                continue
            for source in analytic.get("x_mitre_log_source_references", []):
                name = source.get("name")
                if not name:
                    continue
                logs[tid].add(name)
                if "sysmon" in name.lower():
                    for group in re.findall(r"EventCode\s*=\s*([\d,\s]+)", source.get("channel") or ""):
                        for code in group.split(","):
                            if code.strip().isdigit():
                                codes[tid].add(code.strip())

    revoked: dict[str, str] = {}
    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "revoked-by":
            continue
        source, target = by_id.get(rel["source_ref"]), by_id.get(rel["target_ref"])
        if not source or not target or source.get("type") != "attack-pattern":
            continue
        old, new = external_id(source), external_id(target)
        if old and new and old != new:
            revoked[old] = new

    techniques = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = external_id(obj)
        if not tid or not tid.startswith("T"):
            continue
        techniques[tid] = {
            "name": obj["name"],
            "tactics": [
                p["phase_name"] for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ],
            "sub": bool(obj.get("x_mitre_is_subtechnique")),
            "parent": tid.split(".")[0] if "." in tid else None,
            "platforms": obj.get("x_mitre_platforms", []),
            "log_sources": sorted(logs.get(tid, ())),
            "sysmon_event_codes": sorted(codes.get(tid, ()), key=int),
        }

    return {
        "attack_version": version,
        "tactic_order": order,
        "tactics": tactics,
        "techniques": techniques,
        "revoked": revoked,
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    bundle = json.loads(Path(sys.argv[1]).read_text())
    catalogue = build(bundle)
    Path(sys.argv[2]).write_text(json.dumps(catalogue, separators=(",", ":"), sort_keys=True))
    print(
        f"ATT&CK v{catalogue['attack_version']}: "
        f"{len(catalogue['techniques'])} techniques, {len(catalogue['tactics'])} tactics, "
        f"{len(catalogue['revoked'])} revocations"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
