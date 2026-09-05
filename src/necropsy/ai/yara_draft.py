"""Draft a YARA rule, then prove it is worth keeping.

An LLM will happily produce a plausible-looking YARA rule. Plausible is not the
bar: a rule that does not compile is noise, a rule that does not match the
sample is wrong, and a rule that matches ordinary Windows binaries is worse
than nothing because it will be trusted and then flood a SOC.

So every drafted rule goes through the same gate a human-written one should:

1. It must compile.
2. It must match the sample it was drafted from.
3. It must not match the benign corpus -- the operator's known-good directory
   where one is configured, plus generated controls carrying ordinary imports
   and compiler boilerplate.
4. It must not lean on traits that cannot generalise: the sample's own hashes,
   or a single very short string.

A rule that fails is handed back to the model once or twice with the specific
failure. A rule that still fails is discarded and recorded as a failure, not
stored. The repair prompt explicitly forbids the obvious cheat -- widening the
rule until it matches.
"""

from __future__ import annotations

import logging
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from necropsy.ai.client import AIClient
from necropsy.ai.controls import write_controls
from necropsy.ai.prompts import (
    YARA_DRAFT_TASK,
    YARA_REPAIR_TASK,
    envelope,
    new_nonce,
    system_prompt,
)
from necropsy.ai.schemas import YaraDraft
from necropsy.config import get_settings

log = logging.getLogger(__name__)

try:
    import yara as _yara

    _HAVE_YARA = True
except ImportError:  # pragma: no cover
    _HAVE_YARA = False

# A rule keyed on one three-character string matches half the internet.
MIN_STRING_LENGTH = 6
HASH_PATTERN = re.compile(r"\b[0-9a-f]{32,64}\b", re.I)


@dataclass
class Validation:
    compiled: bool = False
    matches_sample: bool = False
    false_positives: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    corpus_size: int = 0
    real_goodware: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return (
            self.compiled
            and self.matches_sample
            and not self.false_positives
            and not self.weaknesses
        )

    def failure_text(self) -> str:
        if not self.compiled:
            return f"The rule did not compile: {self.error}"
        if not self.matches_sample:
            return "The rule compiled but did not match the sample it must detect."
        if self.false_positives:
            return (
                "The rule matched benign control files: "
                + ", ".join(self.false_positives)
                + ". It is keying on something ordinary software also has."
            )
        if self.weaknesses:
            return "The rule has traits that will not generalise: " + "; ".join(self.weaknesses)
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "compiled": self.compiled, "matches_sample": self.matches_sample,
            "false_positives": self.false_positives, "weaknesses": self.weaknesses,
            "corpus_size": self.corpus_size, "real_goodware": self.real_goodware,
            "error": self.error,
        }


@dataclass
class DraftResult:
    draft: YaraDraft | None
    validation: Validation
    attempts: int
    accepted: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "attempts": self.attempts,
            "validation": self.validation.to_dict(),
            "rule_name": self.draft.rule_name if self.draft else None,
            "confidence": self.draft.confidence if self.draft else None,
            "false_positive_risk": self.draft.false_positive_risk if self.draft else None,
        }


def benign_corpus(scratch: Path) -> tuple[list[Path], bool]:
    """Operator goodware where configured, plus generated controls."""
    settings = get_settings()
    corpus: list[Path] = []
    real = False

    configured = settings.ai_goodware_dir
    if configured:
        root = Path(configured).expanduser()
        if root.is_dir():
            corpus.extend(p for p in sorted(root.rglob("*")) if p.is_file())
            real = bool(corpus)

    corpus.extend(write_controls(scratch / "controls"))
    return corpus, real


def validate(rule_text: str, sample_path: Path, corpus: list[Path], *, real: bool) -> Validation:
    result = Validation(corpus_size=len(corpus), real_goodware=real)
    if not _HAVE_YARA:
        result.error = "yara-python not installed; the rule could not be validated"
        return result

    try:
        compiled = _yara.compile(source=rule_text)
    except Exception as exc:  # noqa: BLE001 - a bad draft is data, not a crash
        result.error = f"{type(exc).__name__}: {exc}"
        return result
    result.compiled = True

    try:
        result.matches_sample = bool(compiled.match(str(sample_path), timeout=60))
    except Exception as exc:  # noqa: BLE001
        result.error = f"matching the sample failed: {exc}"
        return result

    for benign in corpus:
        try:
            if compiled.match(str(benign), timeout=30):
                result.false_positives.append(benign.name)
        except Exception:  # noqa: BLE001 - an unreadable control is not a rule failure
            continue

    result.weaknesses = _weaknesses(rule_text, sample_path)
    return result


def _weaknesses(rule_text: str, sample_path: Path) -> list[str]:
    """Traits that make a rule useless on the next build of the same malware."""
    weaknesses: list[str] = []

    for match in HASH_PATTERN.findall(rule_text):
        weaknesses.append(
            f"keys on a literal hash ({match[:12]}...), which changes with every build"
        )
        break

    literals = re.findall(r'"((?:[^"\\]|\\.)*)"', rule_text)
    # Ignore meta values: only string definitions ($x = "...") are matched on.
    definitions = re.findall(r'\$\w*\s*=\s*"((?:[^"\\]|\\.)*)"', rule_text)
    short = [s for s in definitions if len(s) < MIN_STRING_LENGTH]
    if short and len(short) == len(definitions):
        weaknesses.append(
            f"every string is shorter than {MIN_STRING_LENGTH} characters, which will match widely"
        )

    if not definitions and "uint" not in rule_text and "pe." not in rule_text:
        weaknesses.append("the rule has no strings and no structural conditions")

    if sample_path.name in literals:
        weaknesses.append("keys on the sample's filename, which the attacker controls")

    return weaknesses


def draft(
    client: AIClient,
    *,
    sample_path: Path,
    context: str,
    sample_sha256: str,
) -> DraftResult:
    """Draft, validate, repair up to the configured limit, accept or discard."""
    settings = get_settings()
    nonce = new_nonce()
    system = system_prompt(YARA_DRAFT_TASK, nonce)
    user = envelope(context, nonce, label="case-findings")

    with tempfile.TemporaryDirectory(prefix="necropsy-yara-") as tmp:
        corpus, real = benign_corpus(Path(tmp))

        attempt = 0
        current: YaraDraft | None = None
        validation = Validation()

        while attempt <= settings.ai_yara_repair_attempts:
            attempt += 1
            if current is None:
                current = client.parse(system=system, user=user, schema=YaraDraft)
            else:
                repair_system = system_prompt(YARA_DRAFT_TASK + "\n\n" + YARA_REPAIR_TASK, nonce)
                repair_user = (
                    f"{user}\n\nYOUR PREVIOUS RULE:\n{current.rule_text}\n\n"
                    f"VALIDATION FAILURE:\n{validation.failure_text()}"
                )
                current = client.parse(
                    system=repair_system, user=repair_user, schema=YaraDraft
                )

            validation = validate(current.rule_text, sample_path, corpus, real=real)
            if validation.ok:
                return DraftResult(current, validation, attempt, accepted=True)

            log.info(
                "drafted YARA rule failed validation (attempt %d): %s",
                attempt, validation.failure_text(),
            )

        return DraftResult(current, validation, attempt, accepted=False)


def have_yara() -> bool:
    return _HAVE_YARA
