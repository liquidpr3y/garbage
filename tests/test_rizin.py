"""rizin is enrichment, never a gate.

Neither rizin nor a real binary is present in CI, so these tests drive a stub
that emits rizin-shaped output. That validates discovery, invocation, parsing
and the absence path. The field mapping itself still wants a smoke test
against the rizin build on the analysis Mac -- rz-bin's JSON keys have moved
between releases, which is why the parser is written defensively.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from necropsy.analysis import rizin


@pytest.fixture
def stub_rizin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    binary = tmp_path / "rizin"
    binary.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        '  *-v*) echo "rizin 0.7.3 @ linux-x86-64"; exit 0;;\n'
        "esac\n"
        'for a in "$@"; do\n'
        '  case "$a" in\n'
        '    ij) echo \'{"core":{"format":"pe64"},"bin":{"bintype":"pe","arch":"x86",'
        '"bits":64,"os":"windows","stripped":false,"canary":false,"nx":true,"pic":false}}\';;\n'
        '    iej) echo \'[{"vaddr":5368713216,"paddr":1024,"type":"program"}]\';;\n'
        '    ilj) echo \'["kernel32.dll","advapi32.dll"]\';;\n'
        '    aflc) echo "37";;\n'
        "  esac\n"
        "done\n"
    )
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("NECROPSY_RIZIN_PATH", str(binary))
    from necropsy.config import get_settings

    get_settings.cache_clear()
    return binary


def test_absent_rizin_is_reported_not_raised(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(rizin.shutil, "which", lambda _: None)
    monkeypatch.delenv("NECROPSY_RIZIN_PATH", raising=False)
    from necropsy.config import get_settings

    get_settings.cache_clear()

    result = rizin.triage(tmp_path / "whatever.exe")
    assert result.available is False
    assert "not found" in (result.error or "")


def test_stub_output_is_parsed(stub_rizin: Path, loader_sample: Path) -> None:
    result = rizin.triage(loader_sample)
    assert result.available is True
    assert result.version and result.version.startswith("rizin")
    assert result.function_count == 37
    assert result.binary_info["arch"] == "x86"
    assert result.binary_info["bits"] == 64
    assert "kernel32.dll" in result.libraries
    assert result.entrypoints == ["0x140001000"]
    assert result.error is None


def test_a_failing_rizin_degrades_without_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, loader_sample: Path
) -> None:
    binary = tmp_path / "rizin"
    binary.write_text("#!/bin/sh\necho 'boom' >&2\nexit 3\n")
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("NECROPSY_RIZIN_PATH", str(binary))
    from necropsy.config import get_settings

    get_settings.cache_clear()

    result = rizin.triage(loader_sample)
    assert result.available is True
    assert result.error and "exited 3" in result.error


def test_malformed_json_is_tolerated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, loader_sample: Path
) -> None:
    binary = tmp_path / "rizin"
    binary.write_text("#!/bin/sh\necho 'not json at all'\necho '{broken'\nexit 0\n")
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("NECROPSY_RIZIN_PATH", str(binary))
    from necropsy.config import get_settings

    get_settings.cache_clear()

    result = rizin.triage(loader_sample)
    assert result.available is True
    assert result.binary_info.get("arch") is None
