from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from necropsy.api.deps import db_session
from necropsy.db.repos import cases as cases_repo, jobs as jobs_repo
from necropsy.schemas.job import JobOut

router = APIRouter(tags=["jobs"])


@router.get("/jobs/{job_id}", response_model=JobOut)
def get_job(job_id: str, session: Session = Depends(db_session)) -> Any:
    job = jobs_repo.get(session, job_id)
    if job is None:
        raise HTTPException(404, "job not found")
    return job


@router.get("/cases/{case_id}/jobs", response_model=list[JobOut])
def list_case_jobs(case_id: str, session: Session = Depends(db_session)) -> Any:
    if cases_repo.get(session, case_id) is None:
        raise HTTPException(404, "case not found")
    return jobs_repo.for_case(session, case_id)
