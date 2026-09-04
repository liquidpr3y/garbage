"""Sample hashing.

One streaming pass computes every cryptographic digest plus the TLSH window,
because a sample can be large and we do not want to read it three times.

Fuzzy hashing is deliberately layered by licence, not just by quality:
TLSH is Apache-2.0 and imported directly, while ssdeep's libfuzzy is GPL-2 and
is therefore shelled out to as an external process, never linked. Same
reasoning as Nmap in the pentest module -- see docs/ARCHITECTURE.md S7.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

try:  # optional: pip install necropsy[analysis]
    import tlsh as _tlsh

    _HAVE_TLSH = True
except ImportError:  # pragma: no cover - exercised by the degraded-path test
    _HAVE_TLSH = False

CHUNK = 1024 * 1024

# TLSH needs a floor of input with enough variation; below it the library
# returns a null digest rather than something clusterable.
TLSH_MIN_BYTES = 50


@dataclass(frozen=True)
class Hashes:
    sha256: str
    sha1: str
    md5: str
    size: int
    tlsh: str | None = None
    ssdeep: str | None = None


def hash_file(path: Path, *, want_ssdeep: bool = False) -> Hashes:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    fuzzy = _tlsh.Tlsh() if _HAVE_TLSH else None
    size = 0

    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            size += len(chunk)
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
            if fuzzy is not None:
                fuzzy.update(chunk)

    digest = None
    if fuzzy is not None and size >= TLSH_MIN_BYTES:
        try:
            fuzzy.final()
            digest = fuzzy.hexdigest()
        except (ValueError, RuntimeError):
            # Too little entropy to characterise. Not an error -- some samples
            # genuinely are not clusterable this way.
            digest = None

    return Hashes(
        sha256=sha256.hexdigest(),
        sha1=sha1.hexdigest(),
        md5=md5.hexdigest(),
        size=size,
        tlsh=digest,
        ssdeep=ssdeep_file(path) if want_ssdeep else None,
    )


def ssdeep_file(path: Path) -> str | None:
    """Shell out to the ssdeep binary. Returns None if it is not installed.

    Subprocess rather than the Python bindings on purpose: libfuzzy is GPL-2
    and we keep GPL code at arm's length so a future distributable stays clean.
    """
    binary = shutil.which("ssdeep")
    if not binary:
        return None
    try:
        out = subprocess.run(
            [binary, "-b", "-s", str(path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    lines = [ln for ln in out.stdout.splitlines() if ln.strip()]
    if len(lines) < 2:
        return None
    # "blocksize:h1:h2,filename" -- keep the digest, drop the filename.
    return lines[-1].rsplit(",", 1)[0].strip() or None


def tlsh_distance(a: str, b: str) -> int | None:
    """Distance between two TLSH digests. Lower is more similar; 0 is identical.

    Roughly: <30 is a strong match, <70 worth a human look. Used for the
    Phase 1 hash pivot and, later, sample clustering.
    """
    if not _HAVE_TLSH or not a or not b:
        return None
    try:
        return int(_tlsh.diff(a, b))
    except (ValueError, TypeError):
        return None


def have_tlsh() -> bool:
    return _HAVE_TLSH
