"""RQ worker bootstrap.

Three queues so an eight-minute Ghidra pass never starves an intake, and so
detonation can be pinned to concurrency 1 -- the lab has one set of snapshots
and two samples must never share them.
"""

from __future__ import annotations

from necropsy.config import get_settings
from necropsy.jobs.runner import QUEUE_DETONATE, QUEUE_HEAVY, QUEUE_TRIAGE

ALL_QUEUES = [QUEUE_TRIAGE, QUEUE_HEAVY, QUEUE_DETONATE]


def connection():  # type: ignore[no-untyped-def]
    import redis as redis_lib

    return redis_lib.Redis.from_url(get_settings().redis_url)


def run_worker(queues: list[str] | None = None, *, burst: bool = False) -> None:
    from rq import Worker

    from necropsy.db.session import get_engine
    from necropsy.runtime import get_host

    # Establish the process's engine and host before the first job arrives.
    get_engine()
    get_host()

    worker = Worker(queues or ALL_QUEUES, connection=connection())
    worker.work(burst=burst)
