"""Mirror findings into Elastic so a case is pivotable beside raw telemetry.

The other direction of the bidirectional decision: Phase 3 reads Sysmon out of
the lab's cluster, this writes Necropsy's own findings back into it as ECS
documents. A hunter in Kibana can then pivot from a finding to the events that
produced it without leaving the SIEM.

Two constraints hold this to being a mirror rather than a system of record:

* SQLite stays authoritative. Every write is best-effort; a failure leaves
  ``mirrored_at`` null and `necropsy reindex` retries it later. A SIEM outage
  must never fail an ingest or lose a finding.
* Writes are idempotent per finding, so a replay does not duplicate rows.
"""

from __future__ import annotations

import logging
from typing import Any

from necropsy.db.models import Finding
from necropsy.elastic.client import ElasticClient, ElasticError
from necropsy.sinks.base import to_ecs

log = logging.getLogger(__name__)

DATA_STREAM = "necropsy-findings-default"
TEMPLATE_NAME = "necropsy-findings"
INDEX_PATTERN = "necropsy-findings-*"

INDEX_TEMPLATE: dict[str, Any] = {
    "index_patterns": [INDEX_PATTERN],
    "data_stream": {},
    "priority": 200,
    "template": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "message": {"type": "text"},
                "event": {
                    "properties": {
                        "kind": {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "module": {"type": "keyword"},
                        "dataset": {"type": "keyword"},
                        "severity": {"type": "long"},
                        "risk_score": {"type": "float"},
                    }
                },
                "threat": {
                    "properties": {
                        "framework": {"type": "keyword"},
                        "technique": {
                            "properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}
                        },
                        "tactic": {
                            "properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}
                        },
                    }
                },
                "file": {"properties": {"hash": {"properties": {"sha256": {"type": "keyword"}}}}},
                "necropsy": {
                    "properties": {
                        "case_id": {"type": "keyword"},
                        "finding_id": {"type": "keyword"},
                        "job_id": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "confidence": {"type": "float"},
                        "kill_chain_phase": {"type": "keyword"},
                        "description": {"type": "text"},
                        # Producer-specific and schema-free by design; indexing it
                        # would fight every new producer.
                        "evidence": {"type": "object", "enabled": False},
                    }
                },
            }
        }
    },
}


class ElasticFindingSink:
    """Best-effort mirror of findings into an Elastic data stream."""

    name = "elastic"

    def __init__(self, client: ElasticClient, *, stream: str = DATA_STREAM) -> None:
        self._client = client
        self._stream = stream
        self._template_ready = False

    @classmethod
    def try_from_settings(cls) -> ElasticFindingSink | None:
        client = ElasticClient.try_from_settings()
        return cls(client) if client is not None else None

    def ensure_template(self) -> bool:
        if self._template_ready:
            return True
        try:
            self._client.ensure_index_template(TEMPLATE_NAME, INDEX_TEMPLATE)
            self._template_ready = True
        except (ElasticError, Exception) as exc:  # noqa: BLE001
            log.warning("could not install the necropsy findings template: %s", exc)
            return False
        return True

    def emit(self, finding: Finding) -> str | None:
        if not self.ensure_template():
            return None
        try:
            indexed, errors = self._client.bulk_index(self._stream, [to_ecs(finding)])
        except Exception as exc:  # noqa: BLE001 - a sink must never raise into a job
            log.warning("finding mirror failed for %s: %s", finding.id, exc)
            return None
        if errors or not indexed:
            log.warning("finding mirror rejected %s: %s", finding.id, errors[:1])
            return None
        # Data streams assign their own document id; the finding id is the
        # stable handle on both sides, so record that rather than a generated one.
        return finding.id

    def emit_many(self, findings: list[Finding]) -> tuple[int, list[str]]:
        if not findings or not self.ensure_template():
            return 0, ["template unavailable"]
        try:
            return self._client.bulk_index(self._stream, [to_ecs(f) for f in findings])
        except Exception as exc:  # noqa: BLE001
            return 0, [str(exc)]


def install_if_configured() -> str:
    """Wire the Elastic sink when a cluster is configured. Returns what happened."""
    from necropsy.sinks.base import set_sink

    sink = ElasticFindingSink.try_from_settings()
    if sink is None:
        return "no Elastic configured; findings are not mirrored"
    set_sink(sink)
    return f"findings mirror to {DATA_STREAM}"
