from __future__ import annotations

from pathlib import Path

import pytest

from necropsy.analysis import pe as pe_mod

pytestmark = pytest.mark.skipif(not pe_mod.have_lief(), reason="LIEF not installed")


def test_imports_and_imphash(loader_sample: Path) -> None:
    info = pe_mod.parse(loader_sample)
    assert info.parsed_with == "lief"
    assert set(info.imports) == {"kernel32.dll", "advapi32.dll", "wininet.dll"}
    assert "CreateRemoteThread" in info.imported_functions
    assert info.import_count == 12
    assert info.imphash and len(info.imphash) == 32


def test_writable_executable_section_is_visible(loader_sample: Path) -> None:
    info = pe_mod.parse(loader_sample)
    wx = [s.name for s in info.sections if s.write_execute]
    assert wx == [".packed"]


def test_tls_callbacks_debug_path_and_overlay(tmp_path: Path) -> None:
    from pebuilder import PESpec, build

    spec = PESpec(
        imports={"kernel32.dll": ["Sleep"]},
        tls_callbacks=3,
        pdb_path=r"C:\build\agent\loader.pdb",
        overlay=b"A" * 5000,
    )
    info = pe_mod.parse(build(tmp_path / "x.exe", spec))
    assert len(info.tls_callbacks) == 3
    assert info.pdb_path == r"C:\build\agent\loader.pdb"
    assert info.overlay_size == 5000


def test_entrypoint_section_is_resolved(loader_sample: Path) -> None:
    assert pe_mod.parse(loader_sample).entrypoint_section == ".text"


def test_unsigned_is_reported(loader_sample: Path) -> None:
    assert pe_mod.parse(loader_sample).signed is False


def test_malformed_pe_returns_an_error_not_an_exception(tmp_path: Path) -> None:
    broken = tmp_path / "broken.exe"
    broken.write_bytes(b"MZ" + b"\xff" * 4000)
    info = pe_mod.parse(broken)
    assert info.parsed_with == "lief"
    assert info.error or not info.sections


def test_non_pe_is_rejected_cleanly(tmp_path: Path) -> None:
    blob = tmp_path / "notpe.bin"
    blob.write_bytes(b"%PDF-1.7" + b"0" * 1000)
    assert pe_mod.parse(blob).error is not None
