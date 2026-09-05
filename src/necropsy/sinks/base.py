"""Where findings go besides SQLite.

Elastic is bidirectional by design: Necropsy ships telemetry to the lab's
existing cluster, queries it back for correlation, and mirrors its own findings
into a ``necropsy-findings-*`` ECS data stream so a case is pivotable in Kibana
beside raw Sysmon and Zeek data.

Two rules keep that from becoming a liability:

* SQLite stays the system of record. The mirror is best-effort and replayable --
  a SIEM outage must never fail an ingest or lose a finding. Hence the
  ``elastic_doc_id`` / ``mirrored_at`` columns and ``necropsy reindex``.
* The interface exists in Phase 1 with a no-op default, so nothing in CI or on a
  laptop away from the lab needs a cluster to run.

The Elastic implementation lands in Phase 4.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol

from necropsy.db.models import Finding


class FindingSink(Protocol):
    def emit(self, finding: Finding) -> str | None:
        """Mirror a finding. Returns the external document id, or None.

        Implementations must never raise on transport failure -- return None and
        leave ``mirrored_at`` unset so the backfill can retry.
        """

    @property
    def name(self) -> str: ...


class NullSink:
    """Default. Records nothing, fails never."""

    name = "null"

    def emit(self, finding: Finding) -> str | None:  # noqa: ARG002
        return None


def to_ecs(finding: Finding) -> dict[str, Any]:
    """Map a Finding onto ECS.

    Written now, unused until Phase 4, because the field mapping is an
    architectural decision (it determines what you can pivot on in Kibana) and
    it is cheaper to agree on it before findings accumulate.
    """
    doc: dict[str, Any] = {
        "@timestamp": (finding.created_at or datetime.now(timezone.utc)).isoformat(),
        "event": {
            "kind": "signal",
            "category": ["malware"],
            "module": "necropsy",
            "dataset": f"necropsy.{finding.producer.value}",
            "severity": _severity_number(finding.severity.value),
            "risk_score": round(finding.confidence * 100),
        },
        "message": finding.title,
        "necropsy": {
            "case_id": finding.case_id,
            "finding_id": finding.id,
            "job_id": finding.job_id,
            "type": finding.type,
            "confidence": finding.confidence,
        },
    }
    if finding.description:
        doc["necropsy"]["description"] = finding.description
    if finding.attack_technique_ids:
        # ECS threat.* is ATT&CK's namespace, so tactic here must be an ATT&CK
        # tactic resolved from the technique -- not our kill chain phase. Putting
        # the kill chain in threat.tactic.name would look right and quietly break
        # every Kibana ATT&CK view that reads it.
        from necropsy.attack.catalogue import get_catalogue

        catalogue = get_catalogue()
        names, ids, tactic_names, tactic_ids = [], [], [], []
        for raw in finding.attack_technique_ids:
            technique = catalogue.resolve(raw)
            ids.append(technique.id)
            names.append(technique.name)
            for tactic in technique.tactics:
                tactic_names.append(catalogue.tactic_name(tactic))
                tactic_id = catalogue.tactic_id(tactic)
                if tactic_id:
                    tactic_ids.append(tactic_id)

        threat = doc.setdefault("threat", {})
        threat["framework"] = "MITRE ATT&CK"
        threat["technique"] = {"id": sorted(set(ids)), "name": sorted(set(names))}
        if tactic_names:
            threat["tactic"] = {"name": sorted(set(tactic_names)), "id": sorted(set(tactic_ids))}

    if finding.kill_chain_phase:
        doc["necropsy"]["kill_chain_phase"] = finding.kill_chain_phase.value
    if finding.evidence:
        doc["necropsy"]["evidence"] = finding.evidence
    return doc


_SEVERITY_NUMBERS = {"info": 1, "low": 3, "medium": 5, "high": 7, "critical": 9}


def _severity_number(severity: str) -> int:
    return _SEVERITY_NUMBERS.get(severity, 1)


_sink: FindingSink = NullSink()


def get_sink() -> FindingSink:
    return _sink


def set_sink(sink: FindingSink) -> None:
    global _sink
    _sink = sink
