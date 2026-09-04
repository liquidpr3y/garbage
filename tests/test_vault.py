"""The vault carries the Phase 1 safety invariants, so it gets the most tests."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from necropsy.intake.vault import Vault, VaultError, VaultIntegrityError


@pytest.fixture
def vault(tmp_path: Path) -> Vault:
    return Vault(tmp_path / "vault", os.urandom(32))


def _store(vault: Vault, tmp_path: Path, data: bytes) -> str:
    src = tmp_path / "in.bin"
    src.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    vault.put(src, sha)
    return sha


def test_roundtrip_across_chunk_boundaries(vault: Vault, tmp_path: Path) -> None:
    # Deliberately spans several 1MB chunks plus a partial one.
    data = os.urandom(2 * 1024 * 1024 + 1234)
    sha = _store(vault, tmp_path, data)
    assert vault.read_bytes(sha) == data


def test_empty_and_tiny_payloads_roundtrip(vault: Vault, tmp_path: Path) -> None:
    for data in (b"", b"MZ", b"x" * 4095):
        sha = _store(vault, tmp_path, data)
        assert vault.read_bytes(sha) == data


def test_stored_object_is_read_only_and_not_executable(vault: Vault, tmp_path: Path) -> None:
    sha = _store(vault, tmp_path, b"MZ" + os.urandom(2048))
    mode = vault.path_for(sha).stat().st_mode & 0o777
    assert mode == 0o400, f"expected 0o400, got {oct(mode)}"
    assert not mode & 0o111, "vault object must never carry an executable bit"


def test_stored_object_does_not_keep_the_original_extension(vault: Vault, tmp_path: Path) -> None:
    src = tmp_path / "totally-safe.exe"
    src.write_bytes(b"MZ" + os.urandom(512))
    sha = hashlib.sha256(src.read_bytes()).hexdigest()
    ref = vault.put(src, sha)
    assert vault.path_for(sha).suffix == ".bin"
    assert "exe" not in ref.uri


def test_ciphertext_does_not_contain_the_plaintext(vault: Vault, tmp_path: Path) -> None:
    marker = b"EICAR-STYLE-MARKER-STRING-NOT-A-SAMPLE"
    data = marker + os.urandom(4096)
    sha = _store(vault, tmp_path, data)
    assert marker not in vault.path_for(sha).read_bytes()


def test_scratch_file_is_removed_even_when_the_caller_raises(
    vault: Vault, tmp_path: Path
) -> None:
    sha = _store(vault, tmp_path, os.urandom(1024))
    captured: list[Path] = []
    with pytest.raises(ZeroDivisionError):
        with vault.open_plaintext(sha) as path:
            captured.append(path)
            1 / 0
    assert captured and not captured[0].exists()


def test_truncation_is_detected(vault: Vault, tmp_path: Path) -> None:
    sha = _store(vault, tmp_path, os.urandom(3 * 1024 * 1024))
    target = vault.path_for(sha)
    blob = target.read_bytes()
    target.chmod(0o600)
    target.write_bytes(blob[: len(blob) // 2])
    with pytest.raises(VaultIntegrityError):
        vault.read_bytes(sha)


def test_tampering_is_detected(vault: Vault, tmp_path: Path) -> None:
    sha = _store(vault, tmp_path, os.urandom(4096))
    target = vault.path_for(sha)
    blob = bytearray(target.read_bytes())
    blob[-8] ^= 0xFF
    target.chmod(0o600)
    target.write_bytes(bytes(blob))
    with pytest.raises(VaultIntegrityError):
        vault.read_bytes(sha)


def test_wrong_key_cannot_read(vault: Vault, tmp_path: Path) -> None:
    sha = _store(vault, tmp_path, os.urandom(4096))
    other = Vault(vault.root, os.urandom(32))
    with pytest.raises(VaultIntegrityError):
        other.read_bytes(sha)


def test_put_is_idempotent(vault: Vault, tmp_path: Path) -> None:
    data = os.urandom(2048)
    sha = _store(vault, tmp_path, data)
    first = vault.path_for(sha).stat()
    _store(vault, tmp_path, data)
    assert vault.path_for(sha).stat().st_mtime == first.st_mtime


def test_every_read_is_audited(tmp_path: Path) -> None:
    seen: list[tuple[str, dict]] = []
    vault = Vault(tmp_path / "vault", os.urandom(32), audit=lambda a, d: seen.append((a, d)))
    sha = _store(vault, tmp_path, os.urandom(1024))
    vault.read_bytes(sha, actor="alice", reason="identify")

    writes = [d for a, d in seen if a == "vault.write"]
    reads = [d for a, d in seen if a == "vault.read"]
    assert len(writes) == 1
    assert len(reads) == 1
    assert reads[0]["actor"] == "alice"
    assert reads[0]["reason"] == "identify"


def test_missing_sample_raises(vault: Vault) -> None:
    with pytest.raises(VaultError):
        vault.read_bytes("0" * 64)


def test_rejects_non_sha256_addresses(vault: Vault) -> None:
    for bad in ("", "abc", "z" * 64, "../../etc/passwd"):
        with pytest.raises(ValueError):
            vault.path_for(bad)
