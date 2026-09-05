"""Sigma rules compiled to Elastic queries and run against a detonation window.

Sigma is the right shape for the behavioural half of ATT&CK mapping: rules are
portable, community-maintained, and already carry `attack.tXXXX` tags, so a hit
becomes a technique-tagged finding without a lookup table of our own.

The pipeline matters. SigmaHQ rules are written against Sysmon field names
(`TargetObject`, `Image`); the lab's telemetry is ECS (`registry.path`,
`process.executable`). pySigma's sysmon + ecs_windows pipelines do that
translation, and without them every rule would compile to a query that matches
nothing -- silently, which in this codebase is the failure mode we keep
designing against.

Packaged rules live in `attack/rules/`. Point NECROPSY_SIGMA_RULE_PATHS at a
SigmaHQ checkout for the full corpus; each source compiles independently so one
malformed rule costs that file and nothing else.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from necropsy.config import get_settings
from necropsy.elastic.sysmon import TelemetryWindow, host_filter
from necropsy.enums import Severity

log = logging.getLogger(__name__)

PACKAGED_RULES = Path(__file__).parent / "rules"

SIGMA_LEVEL_TO_SEVERITY = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

# Sigma status -> how much to trust a hit. An experimental rule that fires is
# worth showing, but not at the same confidence as a stable one.
STATUS_CONFIDENCE = {
    "stable": 0.9, "test": 0.75, "experimental": 0.6, "deprecated": 0.3, "unsupported": 0.3,
}

try:
    from sigma.backends.elasticsearch import LuceneBackend
    from sigma.collection import SigmaCollection
    from sigma.pipelines.elasticsearch.windows import ecs_windows
    from sigma.pipelines.sysmon import sysmon_pipeline
    from sigma.processing.resolver import ProcessingPipelineResolver

    _HAVE_SIGMA = True
except ImportError:  # pragma: no cover - exercised by the degraded-path test
    _HAVE_SIGMA = False


@dataclass
class CompiledRule:
    id: str
    title: str
    description: str
    level: str
    status: str
    source: str
    query: str
    attack_techniques: list[str] = field(default_factory=list)
    attack_tactics: list[str] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return SIGMA_LEVEL_TO_SEVERITY.get(self.level.lower(), Severity.MEDIUM)

    @property
    def confidence(self) -> float:
        return STATUS_CONFIDENCE.get(self.status.lower(), 0.6)


@dataclass
class RuleSource:
    name: str
    packaged: bool
    rule_count: int = 0
    error: str | None = None


@dataclass
class SigmaHit:
    rule: CompiledRule
    count: int
    samples: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SigmaRunResult:
    available: bool = True
    hits: list[SigmaHit] = field(default_factory=list)
    rules_run: int = 0
    sources: list[RuleSource] = field(default_factory=list)
    error: str | None = None
    field_adaptation: str | None = None
    # True when no rule fired but the window did contain events. That is not a
    # clean sweep; it is a sweep whose result cannot be distinguished from a
    # field-mapping problem.
    inconclusive: bool = False
    note: str | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "rules_run": self.rules_run,
            "hits": [h.rule.id for h in self.hits],
            "hit_count": len(self.hits),
            "techniques": sorted({t for h in self.hits for t in h.rule.attack_techniques}),
            "sources": [
                {"name": s.name, "packaged": s.packaged, "rules": s.rule_count, "error": s.error}
                for s in self.sources
            ],
            "field_adaptation": self.field_adaptation,
            "inconclusive": self.inconclusive,
            "note": self.note,
            "error": self.error,
        }


def have_sigma() -> bool:
    return _HAVE_SIGMA


def rule_files() -> list[tuple[Path, bool]]:
    files: list[tuple[Path, bool]] = [
        (p, True) for p in sorted(PACKAGED_RULES.glob("*.yml"))
    ]
    for extra in get_settings().sigma_rule_paths:
        root = Path(extra).expanduser()
        if root.is_dir():
            files.extend((p, False) for p in sorted(root.glob("**/*.yml")))
        elif root.is_file():
            files.append((root, False))
    return files


@lru_cache(maxsize=1)
def _backend() -> Any:
    resolver = ProcessingPipelineResolver({"sysmon": sysmon_pipeline, "ecs": ecs_windows})
    return LuceneBackend(processing_pipeline=resolver.resolve(["sysmon", "ecs"]))


def _signature() -> tuple[tuple[str, float], ...]:
    out = []
    for path, _packaged in rule_files():
        try:
            out.append((str(path), path.stat().st_mtime))
        except OSError:
            continue
    return tuple(out)


@lru_cache(maxsize=4)
def _compile(signature: tuple[tuple[str, float], ...]) -> tuple[list[CompiledRule], list[RuleSource]]:
    backend = _backend()
    compiled: list[CompiledRule] = []
    sources: list[RuleSource] = []

    for path_str, _mtime in signature:
        path = Path(path_str)
        source = RuleSource(name=path.name, packaged=PACKAGED_RULES in path.parents)
        try:
            collection = SigmaCollection.from_yaml(path.read_text())
            queries = backend.convert(collection)
            for rule, query in zip(collection.rules, queries, strict=False):
                compiled.append(_describe(rule, query, source.name))
            source.rule_count = len(collection.rules)
        except Exception as exc:  # noqa: BLE001 - one bad rule must not blind the set
            source.error = f"{type(exc).__name__}: {exc}"
            log.warning("Sigma source %s failed: %s", path.name, source.error)
        sources.append(source)

    return compiled, sources


def _describe(rule: Any, query: str, source_name: str) -> CompiledRule:
    techniques: list[str] = []
    tactics: list[str] = []
    for tag in rule.tags or []:
        if tag.namespace != "attack":
            continue
        name = tag.name
        if name.startswith("t") and name[1:2].isdigit():
            techniques.append(name.upper())
        else:
            tactics.append(name.replace("_", "-"))

    return CompiledRule(
        id=str(rule.id) if rule.id else f"{source_name}:{rule.title}",
        title=rule.title or "(untitled)",
        description=(rule.description or "").strip(),
        level=str(rule.level.name).lower() if rule.level else "medium",
        status=str(rule.status.name).lower() if rule.status else "experimental",
        source=source_name,
        query=query,
        attack_techniques=sorted(set(techniques)),
        attack_tactics=sorted(set(tactics)),
    )


def compile_rules() -> tuple[list[CompiledRule], list[RuleSource]]:
    if not _HAVE_SIGMA:
        return [], []
    return _compile(_signature())


CASELESS_SUFFIX = ".caseless"


def index_has_caseless(client: Any, index: str) -> bool:
    """Does this index carry the `.caseless` multi-fields pySigma emits?

    pySigma's ecs_windows pipeline maps `Image` to `process.executable.caseless`,
    a multi-field defined by the winlogbeat ECS module. A modern Elastic Agent
    integration may not define it -- and a Lucene query naming a field that does
    not exist matches nothing and raises nothing. That silent zero would be read
    as "no rule fired", i.e. as a clean run. Probe instead of assuming.
    """
    try:
        payload = client._request(
            "GET", f"/{index}/_field_caps?fields=*{CASELESS_SUFFIX}&ignore_unavailable=true"
        )
    except Exception:  # noqa: BLE001 - a probe failure must not stop the sweep
        return True
    return bool(payload.get("fields"))


def strip_caseless(query: str) -> str:
    return query.replace(CASELESS_SUFFIX + ":", ":")


def window_body(rule: CompiledRule, window: TelemetryWindow, *, size: int = 5,
                query: str | None = None) -> dict[str, Any]:
    """A rule's Lucene query, scoped to one detonation."""
    filters: list[dict[str, Any]] = [
        {
            "range": {
                "@timestamp": {"gte": window.start.isoformat(), "lte": window.end.isoformat()}
            }
        },
        {"query_string": {"query": query or rule.query, "analyze_wildcard": True}},
    ]
    if window.host:
        filters.append(host_filter(window.host))
    return {
        "size": size,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"bool": {"filter": filters}},
    }


def run(
    client: Any,
    index: str,
    window: TelemetryWindow,
    *,
    events_in_window: int | None = None,
) -> SigmaRunResult:
    """Run every compiled rule against one detonation window.

    ``events_in_window`` lets the caller pass a count it already has. It is used
    for the sanity check below, which is the whole reason this returns a note
    rather than just a list of hits.
    """
    if not _HAVE_SIGMA:
        return SigmaRunResult(
            available=False,
            error="pySigma not installed; pip install necropsy[sigma]",
        )

    rules, sources = compile_rules()
    result = SigmaRunResult(sources=sources, rules_run=len(rules))

    caseless = index_has_caseless(client, index)
    if not caseless:
        result.field_adaptation = (
            f"{index} has no {CASELESS_SUFFIX} multi-fields, so they were stripped from "
            "every rule query. pySigma emits them for the winlogbeat ECS mapping; without "
            "this rewrite every rule would match nothing and the sweep would look clean. "
            "Consequence: path matching is now case-sensitive, so a rule keyed on "
            "'\\winword.exe' will miss a process logged as 'WINWORD.EXE'. Ingesting with "
            "the winlogbeat ECS module, or adding a lowercase-normalised multi-field, "
            "restores case-insensitive matching."
        )

    for rule in rules:
        query = rule.query if caseless else strip_caseless(rule.query)
        search = client.search(index, window_body(rule, window, query=query))
        if search.error:
            log.debug("sigma rule %s failed: %s", rule.id, search.error)
            continue
        if search.total:
            result.hits.append(
                SigmaHit(rule=rule, count=search.total, samples=search.sources[:5])
            )

    result.hits.sort(key=lambda h: (-_severity_rank(h.rule.severity), -h.count))
    _assess(result, client, index, window, events_in_window)
    return result


def _assess(
    result: SigmaRunResult,
    client: Any,
    index: str,
    window: TelemetryWindow,
    events_in_window: int | None,
) -> None:
    """Decide whether "nothing fired" means anything.

    Rules that reference fields the index does not have -- a text mapping where
    ECS expects keyword, a pipeline mismatch, the wrong index pattern -- match
    nothing and raise nothing. Reporting that as a clean sweep is the same
    failure this codebase guards against everywhere else: a confident negative
    produced by blindness rather than by evidence.
    """
    if result.hits:
        result.note = f"{len(result.hits)} of {result.rules_run} rule(s) matched."
        return

    if events_in_window is None:
        from necropsy.elastic.sysmon import coverage_probe

        probe = client.search(index, coverage_probe(window))
        events_in_window = probe.total

    if not events_in_window:
        result.note = (
            "No rules matched, and the window contained no events at all. Nothing was "
            "swept -- this says nothing about the sample."
        )
        result.inconclusive = True
        return

    result.inconclusive = True
    result.note = (
        f"No rules matched, but the window contains {events_in_window} event(s). Either "
        "the telemetry genuinely does not trip any rule, or the rules reference fields "
        f"this index does not have -- ECS expects keyword mappings for process.executable "
        "and friends, and a Lucene query naming an absent or text-mapped field matches "
        "nothing silently. Verify one rule by hand before treating this as clean."
    )


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
        Severity.HIGH: 3, Severity.CRITICAL: 4,
    }[severity]
