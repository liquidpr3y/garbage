"""The YARA validation gate.

An LLM will produce a plausible rule on demand. These tests are about the gate
that decides whether a plausible rule is a usable one.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from necropsy.ai.controls import write_controls
from necropsy.ai.yara_draft import benign_corpus, have_yara, validate

pytestmark = pytest.mark.skipif(not have_yara(), reason="yara-python not installed")

GOOD_RULE = """
rule Necropsy_Loader_Test {
    meta:
        description = "test rule"
        author = "necropsy-ai"
        severity = "high"
    strings:
        $a = "vssadmin delete shadows" ascii
        $b = "VBoxService" ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}
"""


@pytest.fixture
def corpus(tmp_path: Path):  # type: ignore[no-untyped-def]
    return write_controls(tmp_path / "controls")


def test_a_sound_rule_passes(loader_sample: Path, corpus) -> None:  # type: ignore[no-untyped-def]
    result = validate(GOOD_RULE, loader_sample, corpus, real=False)
    assert result.ok
    assert result.compiled and result.matches_sample
    assert result.false_positives == []


def test_an_uncompilable_rule_is_rejected(loader_sample: Path, corpus) -> None:  # type: ignore[no-untyped-def]
    result = validate("rule Broken { condition: this is not yara }", loader_sample, corpus, real=False)
    assert not result.ok
    assert not result.compiled
    assert "did not compile" in result.failure_text()


def test_a_rule_that_misses_the_sample_is_rejected(loader_sample: Path, corpus) -> None:  # type: ignore[no-untyped-def]
    rule = 'rule Miss { strings: $a = "NOT_IN_THIS_SAMPLE_AT_ALL" ascii condition: $a }'
    result = validate(rule, loader_sample, corpus, real=False)
    assert not result.ok
    assert result.compiled and not result.matches_sample
    assert "did not match the sample" in result.failure_text()


def test_a_rule_that_hits_benign_controls_is_rejected(loader_sample: Path, corpus) -> None:  # type: ignore[no-untyped-def]
    """The failure mode that would flood a SOC."""
    rule = 'rule Broad { strings: $a = "Mozilla/5.0" ascii condition: uint16(0) == 0x5A4D and $a }'
    result = validate(rule, loader_sample, corpus, real=False)
    assert result.matches_sample, "precondition: it does match the sample"
    assert not result.ok
    assert result.false_positives
    assert "benign control files" in result.failure_text()


def test_a_hash_keyed_rule_is_rejected(loader_sample: Path, corpus) -> None:  # type: ignore[no-untyped-def]
    """Matching a hash detects one build and nothing else."""
    digest = hashlib.sha256(loader_sample.read_bytes()).hexdigest()
    rule = f'''rule Hashed {{
        meta: hash = "{digest}"
        strings: $a = "vssadmin delete shadows" ascii
        condition: $a }}'''
    result = validate(rule, loader_sample, corpus, real=False)
    assert not result.ok
    assert any("literal hash" in w for w in result.weaknesses)


def test_a_rule_of_only_tiny_strings_is_rejected(loader_sample: Path, corpus) -> None:  # type: ignore[no-untyped-def]
    rule = 'rule Tiny { strings: $a = "MZ" ascii $b = ".text" ascii condition: all of them }'
    result = validate(rule, loader_sample, corpus, real=False)
    assert not result.ok
    assert any("shorter than" in w for w in result.weaknesses)


def test_a_rule_with_no_strings_or_structure_is_rejected(loader_sample: Path, corpus) -> None:  # type: ignore[no-untyped-def]
    rule = "rule Empty { condition: filesize > 0 }"
    result = validate(rule, loader_sample, corpus, real=False)
    assert not result.ok
    assert any("no strings and no structural" in w for w in result.weaknesses)


def test_synthetic_controls_look_like_ordinary_binaries(tmp_path: Path) -> None:
    """The controls only catch generic rules if they contain generic things."""
    controls = write_controls(tmp_path / "c")
    assert len(controls) >= 3
    for path in controls:
        blob = path.read_bytes()
        assert blob[:2] == b"MZ"
        assert b"KERNEL32.dll" in blob
        assert b"This program cannot be run in DOS mode." in blob


def test_corpus_reports_whether_real_goodware_was_used(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    corpus, real = benign_corpus(tmp_path / "a")
    assert real is False and len(corpus) >= 3

    goodware = tmp_path / "goodware"
    goodware.mkdir()
    (goodware / "real.bin").write_bytes(b"MZ" + b"\x00" * 512)
    monkeypatch.setenv("NECROPSY_AI_GOODWARE_DIR", str(goodware))
    from necropsy.config import get_settings

    get_settings.cache_clear()

    corpus, real = benign_corpus(tmp_path / "b")
    assert real is True
    assert any(p.name == "real.bin" for p in corpus)
