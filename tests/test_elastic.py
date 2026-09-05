"""Elastic client and Sysmon queries.

The live tests run against a real Elasticsearch when NECROPSY_TEST_ELASTIC_URL
points at one, and skip otherwise. They exist because a query DSL mistake is
invisible to a test double: a `term` against a text-mapped field returns zero
hits and no error, which in this pipeline reads as "the sample did nothing".
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from necropsy.elastic.client import ElasticClient, ElasticUnavailable
from necropsy.elastic.sysmon import (
    INTERESTING_EVENTS,
    TelemetryWindow,
    coverage_probe,
    host_filter,
    window_query,
)

LIVE_URL = os.environ.get("NECROPSY_TEST_ELASTIC_URL")
live = pytest.mark.skipif(not LIVE_URL, reason="set NECROPSY_TEST_ELASTIC_URL to run")


def _window(host: str | None = "WIN-LAB-01") -> TelemetryWindow:
    now = datetime.now(timezone.utc)
    return TelemetryWindow(start=now - timedelta(minutes=5), end=now + timedelta(minutes=1), host=host)


# -- query construction, no cluster needed ----------------------------------


def test_window_query_filters_time_and_event_codes() -> None:
    body = window_query(_window())
    filters = body["query"]["bool"]["filter"]
    assert any("range" in f for f in filters)
    codes = next(f for f in filters if "terms" in f)["terms"]["event.code"]
    assert set(codes) == set(INTERESTING_EVENTS)
    assert body["sort"] == [{"@timestamp": {"order": "asc"}}]


def test_host_filter_covers_keyword_and_text_mappings() -> None:
    """A term query against a text field matches nothing and raises nothing."""
    should = host_filter("WIN-LAB-01")["bool"]["should"]
    kinds = {next(iter(clause)) for clause in should}
    assert kinds == {"term", "match_phrase"}

    fields: set[str] = set()
    for clause in should:
        fields.update(clause[next(iter(clause))].keys())
    assert {"host.name", "host.name.keyword", "host.hostname"} <= fields


def test_coverage_probe_has_no_host_filter_and_no_aggregation() -> None:
    """It must work on the badly-mapped index it exists to diagnose."""
    body = coverage_probe(_window())
    assert "aggs" not in body, "aggregating on host.name needs fielddata; text mappings refuse"
    assert body["size"] > 0
    dumped = str(body)
    assert "WIN-LAB-01" not in dumped


def test_unconfigured_elastic_is_reported_not_raised(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("NECROPSY_ELASTIC_URL", raising=False)
    from necropsy.config import get_settings

    get_settings.cache_clear()
    assert ElasticClient.try_from_settings() is None
    with pytest.raises(ElasticUnavailable):
        ElasticClient.from_settings()


def test_an_unreachable_cluster_degrades_to_an_error_result() -> None:
    client = ElasticClient("http://127.0.0.1:9", timeout_s=2)
    result = client.search("anything-*", window_query(_window()))
    assert result.total == 0
    assert result.error


# -- against a real cluster -------------------------------------------------


@pytest.fixture
def live_client():  # type: ignore[no-untyped-def]
    """Skip rather than error when the cluster named by the env var is down.

    Asking for live tests and getting a wall of connection errors tells you
    less than one clear skip line.
    """
    client = ElasticClient(LIVE_URL or "", timeout_s=20)
    try:
        client.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"NECROPSY_TEST_ELASTIC_URL is set but unreachable: {exc}")
    return client


@pytest.fixture
def seeded(live_client):  # type: ignore[no-untyped-def]
    index = "necropsy-test-sysmon"
    now = datetime.now(timezone.utc)
    try:
        live_client._request("DELETE", f"/{index}")
    except Exception:  # noqa: BLE001
        pass
    live_client._request("PUT", f"/{index}", {
        "mappings": {"properties": {
            "@timestamp": {"type": "date"},
            "event": {"properties": {"code": {"type": "keyword"}}},
            # Deliberately analysed text: the mapping that silently breaks term queries.
            "host": {"properties": {"name": {"type": "text"}}},
        }}
    })
    docs = [
        {"@timestamp": (now - timedelta(seconds=30)).isoformat(), "event": {"code": "1"},
         "host": {"name": "WIN-LAB-01"}, "process": {"name": "loader.exe"}},
        {"@timestamp": (now - timedelta(seconds=20)).isoformat(), "event": {"code": "3"},
         "host": {"name": "WIN-LAB-01"}, "destination": {"ip": "185.220.101.44"}},
        {"@timestamp": (now - timedelta(seconds=10)).isoformat(), "event": {"code": "1"},
         "host": {"name": "OTHER-HOST"}, "process": {"name": "notepad.exe"}},
    ]
    indexed, errors = live_client.bulk_index(index, docs)
    assert indexed == 3 and not errors
    live_client._request("POST", f"/{index}/_refresh")
    return index


@live
def test_live_ping(live_client) -> None:  # type: ignore[no-untyped-def]
    assert live_client.ping()["version"]["number"]


@live
def test_live_window_query_scopes_to_the_guest(live_client, seeded) -> None:  # type: ignore[no-untyped-def]
    result = live_client.search(seeded, window_query(_window()))
    assert result.total == 2, "should match WIN-LAB-01 only, on a text-mapped host field"
    assert all(s["host"]["name"] == "WIN-LAB-01" for s in result.sources)


@live
def test_live_coverage_probe_distinguishes_absent_from_misfiltered(
    live_client, seeded
) -> None:  # type: ignore[no-untyped-def]
    """The check that stops 'wrong host filter' being read as 'sample was inert'."""
    missing = live_client.search(seeded, window_query(_window(host="NO-SUCH-HOST")))
    assert missing.total == 0

    probe = live_client.search(seeded, coverage_probe(_window()))
    assert probe.total == 3, "other hosts are reporting, so the filter is wrong, not the sample"


@live
def test_live_query_against_an_empty_index_is_genuinely_empty(live_client) -> None:  # type: ignore[no-untyped-def]
    index = "necropsy-test-empty"
    try:
        live_client._request("DELETE", f"/{index}")
    except Exception:  # noqa: BLE001
        pass
    live_client._request("PUT", f"/{index}", {"mappings": {"properties": {"@timestamp": {"type": "date"}}}})
    assert live_client.search(index, coverage_probe(_window())).total == 0


@live
def test_live_missing_index_does_not_error(live_client) -> None:  # type: ignore[no-untyped-def]
    """ignore_unavailable: a missing index pattern is empty, not a failure."""
    result = live_client.search("necropsy-does-not-exist-*", window_query(_window()))
    assert result.total == 0 and result.error is None
