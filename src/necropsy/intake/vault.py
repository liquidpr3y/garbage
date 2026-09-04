"""Content-addressed encrypted sample store.

Layout: ``{root}/{sha256[0:2]}/{sha256[2:4]}/{sha256}.bin``

The handling rules here are the ones that matter, and they are enforced in code
rather than documented and hoped for (docs/SAFETY.md):

* Written mode 0o400. Never an executable bit, never the original extension.
* Encrypted at rest. The point is not confidentiality against a determined
  local attacker -- it is that XProtect on Apple Silicon will quarantine or
  delete a recognised sample out from under you, and a corrupted case is worse
  than a locked one. It also makes an accidental double-click inert and keeps
  Spotlight out of the vault.
* Decryption only ever lands in a scratch file that is removed in a ``finally``.
* Every read is audited. Chain of custody is not optional.

Encryption is chunked AES-GCM rather than one-shot: a 512MB installer must not
have to fit in memory. Each chunk is authenticated with its own index as
additional data, so chunks cannot be reordered or dropped, and a terminator
chunk makes truncation detectable.
"""

from __future__ import annotations

import os
import struct
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"NCRPV1"
NONCE_PREFIX_LEN = 8
CHUNK = 1024 * 1024
TAG_LEN = 16
TERMINATOR = b"\xff\xff\xff\xff"

AuditHook = Callable[[str, dict[str, object]], None]


class VaultError(RuntimeError):
    pass


class VaultIntegrityError(VaultError):
    """The stored object did not authenticate: tampered, truncated or wrong key."""


@dataclass(frozen=True)
class VaultRef:
    sha256: str
    uri: str
    size: int
    stored_size: int


class Vault:
    def __init__(self, root: Path, key: bytes, audit: AuditHook | None = None) -> None:
        if len(key) != 32:
            raise ValueError("vault key must be 32 bytes")
        self.root = Path(root).expanduser()
        self._key = key
        self._audit = audit or (lambda action, detail: None)
        self.root.mkdir(parents=True, exist_ok=True)
        # 0o700: the vault is not a shared directory, even on a single-user Mac.
        self.root.chmod(0o700)

    # -- addressing ---------------------------------------------------------

    def path_for(self, sha256: str) -> Path:
        sha256 = sha256.lower()
        if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
            raise ValueError(f"not a sha256: {sha256!r}")
        return self.root / sha256[0:2] / sha256[2:4] / f"{sha256}.bin"

    def uri_for(self, sha256: str) -> str:
        return f"necropsy-vault://{sha256}"

    def exists(self, sha256: str) -> bool:
        return self.path_for(sha256).exists()

    # -- write --------------------------------------------------------------

    def put(self, src: Path, sha256: str, *, actor: str = "local") -> VaultRef:
        """Store ``src`` under its content address. Idempotent."""
        dest = self.path_for(sha256)
        plain_size = src.stat().st_size

        if dest.exists():
            self._audit(
                "vault.write",
                {"sha256": sha256, "actor": actor, "result": "already_present"},
            )
            return VaultRef(sha256, self.uri_for(sha256), plain_size, dest.stat().st_size)

        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.parent.chmod(0o700)

        # Write to a temp file in the destination directory so the rename is
        # atomic and a crash can never leave a half-written vault object at a
        # content address that claims to be complete.
        fd, tmp_name = tempfile.mkstemp(dir=dest.parent, prefix=".incoming-", suffix=".tmp")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as out, src.open("rb") as fh:
                _encrypt_stream(fh, out, self._key, aad=sha256.encode())
                out.flush()
                os.fsync(out.fileno())
            tmp.chmod(0o400)
            os.replace(tmp, dest)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

        stored = dest.stat().st_size
        self._audit(
            "vault.write",
            {"sha256": sha256, "actor": actor, "size": plain_size, "stored_size": stored},
        )
        return VaultRef(sha256, self.uri_for(sha256), plain_size, stored)

    def put_bytes(self, data: bytes, *, actor: str = "local") -> VaultRef:
        """Store an in-memory blob under its own content address.

        Derived artifacts -- a strings dump, a decompilation export, later a
        PCAP or a memory dump -- get exactly the same handling as a sample.
        A payload dumped out of a packer is still a payload.
        """
        import hashlib

        sha256 = hashlib.sha256(data).hexdigest()
        fd, tmp_name = tempfile.mkstemp(prefix=".blob-", suffix=".tmp")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            return self.put(tmp, sha256, actor=actor)
        finally:
            tmp.unlink(missing_ok=True)

    # -- read ---------------------------------------------------------------

    @contextmanager
    def open_plaintext(
        self, sha256: str, *, actor: str = "local", reason: str = "analysis"
    ) -> Iterator[Path]:
        """Decrypt to a scratch file for the duration of the block.

        The scratch file is mode 0o400 and is removed in a ``finally``, so a
        failing analysis job cannot leave a live sample lying around the disk.
        """
        dest = self.path_for(sha256)
        if not dest.exists():
            raise VaultError(f"sample {sha256} not in vault")

        scratch_root = self.root.parent / "scratch"
        scratch_root.mkdir(parents=True, exist_ok=True)
        scratch_root.chmod(0o700)
        tmpdir = Path(tempfile.mkdtemp(dir=scratch_root, prefix="read-"))
        out_path = tmpdir / f"{sha256}.bin"

        self._audit("vault.read", {"sha256": sha256, "actor": actor, "reason": reason})
        try:
            with dest.open("rb") as src, out_path.open("wb") as out:
                _decrypt_stream(src, out, self._key, aad=sha256.encode())
            out_path.chmod(0o400)
            yield out_path
        finally:
            if out_path.exists():
                out_path.chmod(0o600)
            out_path.unlink(missing_ok=True)
            try:
                tmpdir.rmdir()
            except OSError:
                pass

    def read_bytes(self, sha256: str, *, actor: str = "local", reason: str = "analysis") -> bytes:
        with self.open_plaintext(sha256, actor=actor, reason=reason) as p:
            return p.read_bytes()

    # -- destroy ------------------------------------------------------------

    def purge(self, sha256: str, *, actor: str = "local", reason: str = "") -> bool:
        dest = self.path_for(sha256)
        if not dest.exists():
            return False
        dest.chmod(0o600)
        dest.unlink()
        self._audit("vault.purge", {"sha256": sha256, "actor": actor, "reason": reason})
        return True


# -- streaming AES-GCM -------------------------------------------------------


def _chunk_nonce(prefix: bytes, index: int) -> bytes:
    return prefix + struct.pack(">I", index)


def _encrypt_stream(src, out, key: bytes, aad: bytes) -> None:  # type: ignore[no-untyped-def]
    aes = AESGCM(key)
    prefix = os.urandom(NONCE_PREFIX_LEN)
    out.write(MAGIC)
    out.write(prefix)

    index = 0
    while chunk := src.read(CHUNK):
        blob = aes.encrypt(_chunk_nonce(prefix, index), chunk, aad + b":%d" % index)
        out.write(struct.pack(">I", len(blob)))
        out.write(blob)
        index += 1

    # Terminator: an authenticated empty chunk. Its absence means the file was
    # truncated, which is otherwise indistinguishable from a short sample.
    final = aes.encrypt(_chunk_nonce(prefix, index), b"", aad + b":final")
    out.write(TERMINATOR)
    out.write(struct.pack(">I", len(final)))
    out.write(final)


def _decrypt_stream(src, out, key: bytes, aad: bytes) -> None:  # type: ignore[no-untyped-def]
    if src.read(len(MAGIC)) != MAGIC:
        raise VaultIntegrityError("bad vault object header")
    prefix = src.read(NONCE_PREFIX_LEN)
    if len(prefix) != NONCE_PREFIX_LEN:
        raise VaultIntegrityError("truncated vault object header")

    aes = AESGCM(key)
    index = 0
    while True:
        raw_len = src.read(4)
        if len(raw_len) != 4:
            raise VaultIntegrityError("vault object ended without a terminator")
        if raw_len == TERMINATOR:
            raw_len = src.read(4)
            if len(raw_len) != 4:
                raise VaultIntegrityError("truncated terminator")
            (size,) = struct.unpack(">I", raw_len)
            blob = src.read(size)
            try:
                aes.decrypt(_chunk_nonce(prefix, index), blob, aad + b":final")
            except InvalidTag as exc:
                raise VaultIntegrityError("vault object failed authentication") from exc
            return

        (size,) = struct.unpack(">I", raw_len)
        blob = src.read(size)
        if len(blob) != size:
            raise VaultIntegrityError("truncated vault chunk")
        try:
            plain = aes.decrypt(_chunk_nonce(prefix, index), blob, aad + b":%d" % index)
        except InvalidTag as exc:
            raise VaultIntegrityError(f"vault chunk {index} failed authentication") from exc
        out.write(plain)
        index += 1
