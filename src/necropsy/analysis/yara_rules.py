"""YARA scanning.

Rules carry their own metadata -- severity, ATT&CK technique, kill chain phase,
confidence -- so a hit becomes a fully-formed finding without a translation
table maintained somewhere else. Adding a rule is therefore the whole job of
adding a detection.

Packaged rules live in `analysis/rules/`. Operator rules are picked up from
`NECROPSY_YARA_RULE_PATHS`, and a broken operator rule must never take the
packaged set down with it, so each source compiles independently.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from necropsy.config import get_settings
from necropsy.enums import KillChainPhase, Severity

try:
    import yara as _yara

    _HAVE_YARA = True
except ImportError:  # pragma: no cover - exercised by the degraded-path test
    _HAVE_YARA = False

log = logging.getLogger(__name__)

PACKAGED_RULES = Path(__file__).parent / "rules"
SCAN_TIMEOUT_S = 60
MAX_STRING_MATCHES = 12


@dataclass
class RuleSource:
    name: str
    path: Path
    packaged: bool
    rule_count: int = 0
    error: str | None = None


@dataclass
class YaraHit:
    rule: str
    namespace: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    matched_strings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        try:
            return Severity(str(self.meta.get("severity", "medium")).lower())
        except ValueError:
            return Severity.MEDIUM

    @property
    def confidence(self) -> float:
        try:
            return max(0.0, min(1.0, float(self.meta.get("confidence", 0.7))))
        except (TypeError, ValueError):
            return 0.7

    @property
    def attack(self) -> list[str]:
        raw = str(self.meta.get("attack", "")).strip()
        return [t.strip() for t in raw.split(",") if t.strip()]

    @property
    def kill_chain_phase(self) -> KillChainPhase | None:
        raw = str(self.meta.get("kill_chain", "")).strip().lower()
        try:
            return KillChainPhase(raw) if raw else None
        except ValueError:
            return None

    @property
    def description(self) -> str:
        return str(self.meta.get("description", self.rule))


@dataclass
class ScanResult:
    hits: list[YaraHit] = field(default_factory=list)
    sources: list[RuleSource] = field(default_factory=list)
    available: bool = True
    error: str | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "hits": [h.rule for h in self.hits],
            "hit_count": len(self.hits),
            "rules_loaded": sum(s.rule_count for s in self.sources),
            "sources": [
                {"name": s.name, "packaged": s.packaged, "rules": s.rule_count,
                 "error": s.error}
                for s in self.sources
            ],
            "error": self.error,
        }


def rule_files() -> list[tuple[Path, bool]]:
    files: list[tuple[Path, bool]] = [(p, True) for p in sorted(PACKAGED_RULES.glob("*.yar"))]
    for extra in get_settings().yara_rule_paths:
        root = Path(extra).expanduser()
        if root.is_dir():
            files.extend((p, False) for p in sorted(root.glob("**/*.yar")))
        elif root.is_file():
            files.append((root, False))
    return files


@lru_cache(maxsize=8)
def _compile(signature: tuple[tuple[str, float], ...]):  # type: ignore[no-untyped-def]
    """Compile every rule source. Keyed on (path, mtime) so edits are picked up."""
    compiled = []
    sources: list[RuleSource] = []
    for path_str, _mtime in signature:
        path = Path(path_str)
        source = RuleSource(name=path.name, path=path, packaged=PACKAGED_RULES in path.parents)
        try:
            rules = _yara.compile(filepath=str(path))
            source.rule_count = sum(1 for _ in rules)
            compiled.append(rules)
        except Exception as exc:  # noqa: BLE001 - one bad rule file must not blind the rest
            source.error = f"{type(exc).__name__}: {exc}"
            log.warning("YARA source %s failed to compile: %s", path, source.error)
        sources.append(source)
    return compiled, sources


def _signature() -> tuple[tuple[str, float], ...]:
    out = []
    for path, _packaged in rule_files():
        try:
            out.append((str(path), path.stat().st_mtime))
        except OSError:
            continue
    return tuple(out)


def scan(path: Path) -> ScanResult:
    if not _HAVE_YARA:
        return ScanResult(available=False, error="yara-python not installed")

    try:
        compiled, sources = _compile(_signature())
    except Exception as exc:  # noqa: BLE001
        return ScanResult(available=False, error=f"rule compilation failed: {exc}")

    result = ScanResult(sources=sources)
    for rules in compiled:
        try:
            matches = rules.match(str(path), timeout=SCAN_TIMEOUT_S)
        except Exception as exc:  # noqa: BLE001
            log.warning("YARA scan failed: %s", exc)
            result.error = f"{type(exc).__name__}: {exc}"
            continue
        for match in matches:
            result.hits.append(
                YaraHit(
                    rule=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta=dict(match.meta),
                    matched_strings=_describe(match),
                )
            )
    return result


def _describe(match: Any) -> list[dict[str, Any]]:
    """Where a rule fired, capped -- evidence, not a data dump."""
    described: list[dict[str, Any]] = []
    for string_match in getattr(match, "strings", [])[:MAX_STRING_MATCHES]:
        identifier = getattr(string_match, "identifier", str(string_match))
        instances = getattr(string_match, "instances", [])
        described.append(
            {
                "identifier": identifier,
                "count": len(instances),
                "first_offset": getattr(instances[0], "offset", None) if instances else None,
            }
        )
    return described


def have_yara() -> bool:
    return _HAVE_YARA
