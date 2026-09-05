"""One detonation at a time.

The lab has one set of snapshots. Two samples sharing them means one run's
telemetry contaminates the other's, and a revert mid-run destroys both. The RQ
`detonate` queue runs at concurrency 1, but that only constrains one worker --
an inline run, a second worker, or a CLI invocation would each bypass it, so
the guarantee lives in a filesystem lock instead.
"""

from __future__ import annotations

import errno
import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from necropsy.config import get_settings


class SandboxBusy(RuntimeError):
    """Another detonation holds the lab."""


@contextmanager
def detonation_lock(*, timeout_s: int = 0) -> Iterator[Path]:
    settings = get_settings()
    lock_path = settings.vault_root.parent / "detonation.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    handle = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                raise
            raise SandboxBusy(
                "another detonation is using the lab; the snapshots cannot be shared"
            ) from exc

        os.ftruncate(handle, 0)
        os.write(handle, f"{os.getpid()}\n".encode())
        yield lock_path
    finally:
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            os.close(handle)
