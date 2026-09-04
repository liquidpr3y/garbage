from __future__ import annotations

from pathlib import Path

import pytest

from necropsy.analysis import yara_rules
from necropsy.enums import KillChainPhase, Severity

pytestmark = pytest.mark.skipif(not yara_rules.have_yara(), reason="yara-python not installed")


@pytest.fixture(autouse=True)
def _clear_rule_cache():  # type: ignore[no-untyped-def]
    yara_rules._compile.cache_clear()
    yield
    yara_rules._compile.cache_clear()


def test_packaged_rules_all_compile(tmp_path: Path) -> None:
    probe = tmp_path / "probe.bin"
    probe.write_bytes(b"nothing interesting here" * 10)
    result = yara_rules.scan(probe)
    assert result.available
    assert result.sources, "no rule sources discovered"
    assert all(s.error is None for s in result.sources), [s.error for s in result.sources]
    assert sum(s.rule_count for s in result.sources) >= 8


def test_hit_carries_severity_attack_and_phase(loader_sample: Path) -> None:
    hits = {h.rule: h for h in yara_rules.scan(loader_sample).hits}
    assert "NECROPSY_Recovery_Destruction" in hits

    hit = hits["NECROPSY_Recovery_Destruction"]
    assert hit.severity is Severity.CRITICAL
    assert hit.attack == ["T1490"]
    assert hit.kill_chain_phase is KillChainPhase.ACTIONS_ON_OBJECTIVES
    assert 0.0 < hit.confidence <= 1.0


def test_clean_sample_produces_no_hits(plain_sample: Path) -> None:
    assert yara_rules.scan(plain_sample).hits == []


def test_operator_rules_are_loaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rules_dir = tmp_path / "myrules"
    rules_dir.mkdir()
    (rules_dir / "local.yar").write_text(
        'rule LOCAL_Canary {\n'
        '  meta:\n    severity = "low"\n    attack = "T1005"\n'
        '    kill_chain = "actions_on_objectives"\n'
        '  strings:\n    $a = "CANARY-TOKEN-XYZ"\n'
        '  condition:\n    $a\n}\n'
    )
    monkeypatch.setenv("NECROPSY_YARA_RULE_PATHS", str(rules_dir))
    from necropsy.config import get_settings

    get_settings.cache_clear()

    target = tmp_path / "hit.bin"
    target.write_bytes(b"padding CANARY-TOKEN-XYZ padding")
    result = yara_rules.scan(target)
    assert "LOCAL_Canary" in [h.rule for h in result.hits]
    assert any(not s.packaged for s in result.sources)


def test_a_broken_operator_rule_does_not_blind_the_packaged_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One bad rule file must cost that file, not the whole detection surface."""
    rules_dir = tmp_path / "broken"
    rules_dir.mkdir()
    (rules_dir / "bad.yar").write_text("rule Broken { this is not yara }")
    monkeypatch.setenv("NECROPSY_YARA_RULE_PATHS", str(rules_dir))
    from necropsy.config import get_settings

    get_settings.cache_clear()

    result = yara_rules.scan(_upx_like(tmp_path))
    assert result.available
    assert any(s.error for s in result.sources if not s.packaged)
    assert "NECROPSY_Packer_UPX" in [h.rule for h in result.hits]


def _upx_like(tmp_path: Path) -> Path:
    from pebuilder import PESpec, build

    return build(
        tmp_path / "upx.exe",
        PESpec(imports={"kernel32.dll": ["Sleep"]},
               extra_rdata_strings=["UPX0", "UPX1", "UPX!"]),
    )
