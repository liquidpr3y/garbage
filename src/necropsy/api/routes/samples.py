from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from necropsy.api.deps import confirm_malware, db_session, host_services
from necropsy.config import get_settings
from necropsy.contracts.host import HostServices
from necropsy.db.repos import cases as cases_repo, samples as samples_repo
from necropsy.enums import SampleSource
from necropsy.intake import service as intake
from necropsy.jobs.runner import get_runner
from necropsy.schemas.sample import (
    CaseSampleOut,
    IngestByPath,
    IngestResponse,
    SampleDetail,
    SampleOut,
)

router = APIRouter(tags=["samples"])


def _respond(session: Session, result: intake.IngestResult) -> IngestResponse:
    return IngestResponse(
        sample=SampleOut.model_validate(result.sample, from_attributes=True),
        new_to_platform=result.sample_created,
        attached_to_case=result.attached,
        also_in_case_count=result.other_case_count,
        identify_job_id=result.job_id,
    )


@router.post(
    "/cases/{case_id}/samples",
    response_model=IngestResponse,
    status_code=201,
    dependencies=[Depends(confirm_malware)],
)
async def ingest_upload(
    case_id: str,
    file: UploadFile = File(...),
    note: str | None = Form(default=None),
    session: Session = Depends(db_session),
    host: HostServices = Depends(host_services),
) -> Any:
    """Stream an uploaded sample to disk, then ingest it.

    Streamed rather than read into memory: a 512MB installer must not become a
    512MB allocation in the API process.
    """
    settings = get_settings()
    tmpdir = Path(tempfile.mkdtemp(prefix="necropsy-upload-"))
    tmp = tmpdir / "upload.bin"
    written = 0
    try:
        with tmp.open("wb") as out:
            while chunk := await file.read(1024 * 1024):
                written += len(chunk)
                if written > settings.max_sample_bytes:
                    raise HTTPException(413, "sample exceeds the configured size cap")
                out.write(chunk)
        tmp.chmod(0o600)

        result = _ingest(
            session,
            host,
            case_id=case_id,
            src=tmp,
            observed_filename=file.filename,
            source=SampleSource.UPLOAD,
            note=note,
        )
        return _respond(session, result)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@router.post(
    "/cases/{case_id}/samples/by-path",
    response_model=IngestResponse,
    status_code=201,
    dependencies=[Depends(confirm_malware)],
)
def ingest_by_path(
    case_id: str,
    body: IngestByPath,
    session: Session = Depends(db_session),
    host: HostServices = Depends(host_services),
) -> Any:
    src = Path(body.path).expanduser()
    if not src.is_file():
        raise HTTPException(400, f"not a readable file: {body.path}")
    result = _ingest(
        session,
        host,
        case_id=case_id,
        src=src,
        observed_filename=body.observed_filename or src.name,
        source=body.source,
        note=body.note,
    )
    return _respond(session, result)


def _ingest(
    session: Session,
    host: HostServices,
    **kwargs: Any,
) -> intake.IngestResult:
    try:
        result = intake.ingest_file(session, host, **kwargs)
    except intake.CaseNotFound:
        raise HTTPException(404, "case not found") from None
    except intake.SampleTooLarge as exc:
        raise HTTPException(413, str(exc)) from None
    except intake.IngestError as exc:
        raise HTTPException(400, str(exc)) from None

    # Commit before submitting: a worker opening its own session cannot see an
    # uncommitted job row.
    session.commit()
    if result.job_id:
        get_runner().submit(result.job_id, "identify")
        session.expire_all()
    return result


@router.get("/cases/{case_id}/samples", response_model=list[CaseSampleOut])
def list_case_samples(case_id: str, session: Session = Depends(db_session)) -> Any:
    if cases_repo.get(session, case_id) is None:
        raise HTTPException(404, "case not found")
    return samples_repo.for_case(session, case_id)


@router.get("/samples/{sha256}", response_model=SampleDetail)
def get_sample(sha256: str, session: Session = Depends(db_session)) -> Any:
    sample = samples_repo.get_by_sha256(session, sha256.lower())
    if sample is None:
        raise HTTPException(404, "sample not found")
    payload = SampleDetail.model_validate(sample, from_attributes=True)
    payload.other_cases = [
        {"id": c.id, "name": c.name} for c in samples_repo.other_cases(session, sample.id)
    ]
    return payload
