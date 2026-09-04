from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from necropsy.api.deps import db_session
from necropsy.db.repos import cases as cases_repo, findings as findings_repo
from necropsy.schemas.finding import FindingOut

router = APIRouter(tags=["findings"])


@router.get("/cases/{case_id}/findings", response_model=list[FindingOut])
def list_case_findings(case_id: str, session: Session = Depends(db_session)) -> Any:
    if cases_repo.get(session, case_id) is None:
        raise HTTPException(404, "case not found")
    return findings_repo.for_case(session, case_id)
