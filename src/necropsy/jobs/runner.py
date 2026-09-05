"""How a queued job actually gets executed.

RQ over Redis is the real topology. ``InlineRunner`` exists so tests and a
laptop away from the lab can run a triage without standing up Redis -- and so
CI never needs a broker.

Submission must always happen *after* the caller commits. A worker opening its
own session cannot see an uncommitted job row, and an inline runner re-entering
an open transaction is worse. Services create job rows; the API and CLI layers
commit and then submit.
"""

from __future__ import annotations

import logging
from typing import Protocol

from necropsy.config import get_settings

log = logging.getLogger(__name__)

# Queue names. Ghidra must never starve an intake, and detonation runs at
# concurrency 1 because the lab has one set of snapshots.
QUEUE_TRIAGE = "necropsy-triage"
QUEUE_HEAVY = "necropsy-heavy"
QUEUE_DETONATE = "necropsy-detonate"

QUEUE_FOR_KIND = {
    "identify": QUEUE_TRIAGE,
    "hash_pivot": QUEUE_TRIAGE,
    "static_triage": QUEUE_TRIAGE,
    "yara_scan": QUEUE_TRIAGE,
    "ghidra_decompile": QUEUE_HEAVY,
    "sigma_sweep": QUEUE_TRIAGE,
    "ai_summarise": QUEUE_HEAVY,
    "ai_report": QUEUE_HEAVY,
    "ai_yara": QUEUE_HEAVY,
    "detonate": QUEUE_DETONATE,
}


class JobRunner(Protocol):
    def submit(self, job_id: str, kind: str) -> str | None:
        """Start the job. Returns a backend job id, if the backend has one."""


class InlineRunner:
    """Execute immediately in the calling process."""

    def submit(self, job_id: str, kind: str) -> str | None:  # noqa: ARG002
        from necropsy.jobs.tasks.base import execute_job

        execute_job(job_id)
        return None


class RQRunner:
    def __init__(self, redis_client: object | None = None) -> None:
        self._redis = redis_client

    def _connection(self) -> object:
        if self._redis is None:
            import redis as redis_lib

            self._redis = redis_lib.Redis.from_url(get_settings().redis_url)
        return self._redis

    def submit(self, job_id: str, kind: str) -> str | None:
        from rq import Queue

        queue = Queue(
            QUEUE_FOR_KIND.get(kind, QUEUE_TRIAGE),
            connection=self._connection(),
        )
        rq_job = queue.enqueue(
            "necropsy.jobs.tasks.base.execute_job",
            job_id,
            job_timeout=3600,
        )
        return str(rq_job.id)


_runner: JobRunner | None = None


def get_runner() -> JobRunner:
    global _runner
    if _runner is None:
        _runner = InlineRunner() if get_settings().job_runner == "inline" else RQRunner()
    return _runner


def set_runner(runner: JobRunner) -> None:
    global _runner
    _runner = runner
