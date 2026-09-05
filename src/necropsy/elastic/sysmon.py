"""Sysmon telemetry queries, in ECS field names.

Field names follow the Elastic Agent Windows integration's ECS mapping, which
is what the lab already ships. Nothing here parses EVTX: the whole point of
the integration decision is that event normalisation happens once, in Elastic,
rather than twice.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Sysmon event IDs that carry behaviour worth a finding.
EVENT_PROCESS_CREATE = "1"
EVENT_NETWORK_CONNECT = "3"
EVENT_IMAGE_LOAD = "7"
EVENT_CREATE_REMOTE_THREAD = "8"
EVENT_FILE_CREATE = "11"
EVENT_REGISTRY_ADD = "12"
EVENT_REGISTRY_SET = "13"
EVENT_REGISTRY_RENAME = "14"
EVENT_PIPE_CREATE = "17"
EVENT_DNS_QUERY = "22"
EVENT_FILE_DELETE = "23"
EVENT_PROCESS_TAMPERING = "25"

INTERESTING_EVENTS = [
    EVENT_PROCESS_CREATE, EVENT_NETWORK_CONNECT, EVENT_IMAGE_LOAD,
    EVENT_CREATE_REMOTE_THREAD, EVENT_FILE_CREATE, EVENT_REGISTRY_ADD,
    EVENT_REGISTRY_SET, EVENT_REGISTRY_RENAME, EVENT_PIPE_CREATE,
    EVENT_DNS_QUERY, EVENT_FILE_DELETE, EVENT_PROCESS_TAMPERING,
]

SOURCE_FIELDS = [
    "@timestamp", "event.code", "event.action", "host.name",
    "process.name", "process.executable", "process.pid", "process.command_line",
    "process.parent.name", "process.parent.executable", "process.parent.pid",
    "destination.ip", "destination.port", "destination.domain",
    "dns.question.name", "registry.path", "registry.value", "registry.data.strings",
    "file.path", "file.name", "user.name", "winlog.event_id",
]


@dataclass
class TelemetryWindow:
    start: datetime
    end: datetime
    host: str | None = None
    extra_terms: dict[str, Any] = field(default_factory=dict)


def window_query(window: TelemetryWindow, *, size: int = 2000) -> dict[str, Any]:
    """Every interesting Sysmon event in the detonation window.

    Sorted ascending because the operator reads this as a timeline, and the
    first few events -- what spawned what -- carry most of the meaning.
    """
    filters: list[dict[str, Any]] = [
        {
            "range": {
                "@timestamp": {
                    "gte": window.start.isoformat(),
                    "lte": window.end.isoformat(),
                }
            }
        },
        {"terms": {"event.code": INTERESTING_EVENTS}},
    ]
    if window.host:
        filters.append(host_filter(window.host))
    for key, value in window.extra_terms.items():
        filters.append({"term": {key: value}})

    return {
        "size": size,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "_source": SOURCE_FIELDS,
        "query": {"bool": {"filter": filters}},
    }


def host_filter(host: str) -> dict[str, Any]:
    """Match the guest across the mappings a host field might actually have.

    `term` against a `text`-mapped field matches nothing and raises nothing:
    the analysed index holds `win-lab-01`, the query asks for `WIN-LAB-01`, and
    the result is a silent zero. On a detonation that silence reads as "the
    sample did nothing", which is the single worst thing this pipeline can
    say. The Elastic Agent integration maps these as `keyword` and a plain
    `term` is correct there, but a hand-rolled or dynamically-mapped index is
    not, so match every shape rather than trusting one.
    """
    fields = ("host.name", "host.hostname", "agent.name", "winlog.computer_name")
    should: list[dict[str, Any]] = []
    for field_name in fields:
        should.append({"term": {field_name: host}})
        should.append({"term": {f"{field_name}.keyword": host}})
        should.append({"match_phrase": {field_name: host}})
    return {"bool": {"should": should, "minimum_should_match": 1}}


def coverage_probe(window: TelemetryWindow) -> dict[str, Any]:
    """Same window, no host filter.

    Run when the host-filtered query comes back empty, to tell two very
    different situations apart: the guest produced no telemetry, or we are
    looking in the wrong place. Only the first is a finding about the sample.
    """
    # Samples rather than a terms aggregation on host.name: aggregating needs
    # fielddata, which is disabled on text-mapped fields -- and a text mapping
    # is exactly the situation this probe exists to diagnose. A probe that
    # errors on the case it was written for is no probe at all.
    return {
        "size": 5,
        "_source": ["@timestamp", "host.name", "host.hostname", "agent.name", "event.code"],
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": window.start.isoformat(),
                                "lte": window.end.isoformat(),
                            }
                        }
                    }
                ]
            }
        },
    }


def count_by_event_code(window: TelemetryWindow) -> dict[str, Any]:
    """Cheap shape-of-the-run query: how much of what happened."""
    body = window_query(window, size=0)
    body["aggs"] = {"by_code": {"terms": {"field": "event.code", "size": 30}}}
    return body
