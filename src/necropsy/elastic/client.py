"""A small Elasticsearch HTTP client.

Deliberately not the official `elasticsearch` package: this needs search, bulk
and a ping, and the official client pins its major version against the server's
in a way that is awkward when the lab upgrades independently of this tool.

Read paths never raise into a job. A SIEM outage during a detonation must cost
the correlation step, not the run -- the PCAP and the sample's own artifacts
are still worth having.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from necropsy.config import get_settings

log = logging.getLogger(__name__)


class ElasticError(RuntimeError):
    pass


class ElasticUnavailable(ElasticError):
    """Not configured, or the cluster could not be reached."""


@dataclass
class SearchResult:
    total: int
    hits: list[dict[str, Any]]
    took_ms: int = 0
    error: str | None = None

    @property
    def sources(self) -> list[dict[str, Any]]:
        return [h.get("_source", {}) for h in self.hits]


class ElasticClient:
    def __init__(
        self,
        url: str,
        *,
        api_key: str | None = None,
        verify: bool = True,
        timeout_s: int = 30,
    ) -> None:
        self.url = url.rstrip("/")
        self._headers = {"content-type": "application/json"}
        if api_key:
            self._headers["authorization"] = f"ApiKey {api_key}"
        self._verify = verify
        self._timeout = timeout_s

    @classmethod
    def from_settings(cls) -> ElasticClient:
        settings = get_settings()
        if not settings.elastic_url:
            raise ElasticUnavailable(
                "NECROPSY_ELASTIC_URL is not set; telemetry correlation is unavailable"
            )
        return cls(
            settings.elastic_url,
            api_key=settings.elastic_api_key,
            verify=settings.elastic_verify_certs,
            timeout_s=settings.elastic_query_timeout_s,
        )

    @classmethod
    def try_from_settings(cls) -> ElasticClient | None:
        try:
            return cls.from_settings()
        except ElasticUnavailable:
            return None

    def _request(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        try:
            with httpx.Client(verify=self._verify, timeout=self._timeout) as client:
                response = client.request(
                    method,
                    f"{self.url}{path}",
                    headers=self._headers,
                    content=json.dumps(body) if body is not None else None,
                )
        except httpx.HTTPError as exc:
            raise ElasticUnavailable(f"{type(exc).__name__}: {exc}") from exc

        if response.status_code >= 400:
            raise ElasticError(
                f"elasticsearch {method} {path} -> {response.status_code}: "
                f"{response.text[:400]}"
            )
        return response.json() if response.content else {}

    # -- read ---------------------------------------------------------------

    def ping(self) -> dict[str, Any]:
        return self._request("GET", "/")

    def search(self, index: str, body: dict[str, Any]) -> SearchResult:
        try:
            payload = self._request("POST", f"/{index}/_search?ignore_unavailable=true", body)
        except ElasticError as exc:
            return SearchResult(total=0, hits=[], error=str(exc))

        hits = payload.get("hits", {})
        total = hits.get("total", {})
        return SearchResult(
            total=total.get("value", 0) if isinstance(total, dict) else int(total or 0),
            hits=hits.get("hits", []),
            took_ms=payload.get("took", 0),
        )

    # -- write (used by the Phase 4 finding mirror) -------------------------

    def bulk_index(self, index: str, documents: list[dict[str, Any]]) -> tuple[int, list[str]]:
        """Index documents. Returns (indexed, errors)."""
        if not documents:
            return 0, []
        lines: list[str] = []
        for doc in documents:
            lines.append(json.dumps({"create": {}}))
            lines.append(json.dumps(doc))
        body = "\n".join(lines) + "\n"

        try:
            with httpx.Client(verify=self._verify, timeout=self._timeout) as client:
                response = client.post(
                    f"{self.url}/{index}/_bulk",
                    headers={**self._headers, "content-type": "application/x-ndjson"},
                    content=body,
                )
        except httpx.HTTPError as exc:
            raise ElasticUnavailable(f"{type(exc).__name__}: {exc}") from exc

        if response.status_code >= 400:
            raise ElasticError(f"bulk -> {response.status_code}: {response.text[:400]}")

        payload = response.json()
        errors: list[str] = []
        indexed = 0
        for item in payload.get("items", []):
            outcome = item.get("create") or item.get("index") or {}
            if outcome.get("error"):
                errors.append(json.dumps(outcome["error"])[:200])
            else:
                indexed += 1
        return indexed, errors

    def ensure_index_template(self, name: str, template: dict[str, Any]) -> None:
        self._request("PUT", f"/_index_template/{name}", template)
