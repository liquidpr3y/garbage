"""Cross-case hash pivot.

Exact matches answer "have we seen these bytes before". TLSH near neighbours
answer the more useful question: "have we seen something built from the same
source or packed by the same kit". Both are offline and cost nothing, which is
why this is the lowest-risk proposal offered after intake.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from necropsy.contracts.host import HostServices
from necropsy.db.models import AnalysisJob
from necropsy.db.repos import samples as samples_repo
from necropsy.enums import Producer, Severity
from necropsy.intake.hashing import have_tlsh, tlsh_distance
from necropsy.jobs.tasks.base import emit_finding

# TLSH distance bands. Below STRONG the two files are near-certainly related;
# between STRONG and WORTH_A_LOOK a human should decide.
TLSH_STRONG = 30
TLSH_WORTH_A_LOOK = 70


def run(session: Session, host: HostServices, job: AnalysisJob) -> dict[str, Any]:
    sample = samples_repo.get(session, job.sample_id) if job.sample_id else None
    if sample is None:
        raise RuntimeError(f"job {job.id} has no sample to pivot on")

    exact = samples_repo.other_cases(session, sample.id, exclude_case_id=job.case_id)

    neighbours: list[dict[str, Any]] = []
    if sample.tlsh and have_tlsh():
        for other in samples_repo.with_tlsh(session, exclude_sample_id=sample.id):
            distance = tlsh_distance(sample.tlsh, other.tlsh or "")
            if distance is not None and distance <= TLSH_WORTH_A_LOOK:
                neighbours.append(
                    {
                        "sample_id": other.id,
                        "sha256": other.sha256,
                        "distance": distance,
                        "file_type": other.file_type.value,
                        "cases": [c.name for c in samples_repo.other_cases(session, other.id)],
                    }
                )
    neighbours.sort(key=lambda n: n["distance"])

    if exact:
        emit_finding(
            session, host, job,
            producer=Producer.CORRELATION,
            type="exact_hash_match",
            title=f"Identical sample in {len(exact)} other case(s)",
            dedupe_key=f"exact_hash_match:{sample.sha256}",
            description="Same bytes, different case. Prior analysis may already answer this.",
            severity=Severity.INFO,
            confidence=1.0,
            evidence={"case_ids": [c.id for c in exact], "case_names": [c.name for c in exact]},
        )

    strong = [n for n in neighbours if n["distance"] <= TLSH_STRONG]
    if strong:
        emit_finding(
            session, host, job,
            producer=Producer.CORRELATION,
            type="fuzzy_hash_cluster",
            title=f"{len(strong)} near-identical sample(s) by TLSH (distance <= {TLSH_STRONG})",
            dedupe_key=f"fuzzy_hash_cluster:{sample.sha256}",
            description=(
                "Structurally near-identical to samples already held. Typically a rebuild, "
                "a reconfigured builder output, or the same packer over different payloads."
            ),
            severity=Severity.LOW,
            confidence=0.8,
            evidence={"neighbours": strong[:20]},
        )

    return {
        "exact_matches": len(exact),
        "tlsh_neighbours": len(neighbours),
        "tlsh_strong": len(strong),
        "tlsh_available": have_tlsh(),
    }
