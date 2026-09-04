from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from necropsy.api.deps import db_session, host_services
from necropsy.cases import service as case_service
from necropsy.contracts.host import HostServices
from necropsy.db.repos import cases as cases_repo
from necropsy.enums import CaseStatus
from necropsy.schemas.case import CaseCreate, CaseDetail, CaseOut, CaseUpdate

router = APIRouter(tags=["cases"])


@router.post("/cases", response_model=CaseOut, status_code=201)
def create_case(
    body: CaseCreate,
    session: Session = Depends(db_session),
    host: HostServices = Depends(host_services),
) -> Any:
    case = case_service.create_case(
        session,
        host,
        name=body.name,
        severity=body.severity,
        tags=body.tags,
        host_engagement_ref=body.host_engagement_ref,
        ai_disclosure_allowed=body.ai_disclosure_allowed,
    )
    session.commit()
    return case


@router.get("/cases", response_model=list[CaseOut])
def list_cases(
    status: CaseStatus | None = None,
    tag: str | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
    session: Session = Depends(db_session),
) -> Any:
    return cases_repo.list_cases(session, status=status, tag=tag, limit=limit, offset=offset)


@router.get("/cases/{case_id}", response_model=CaseDetail)
def get_case(case_id: str, session: Session = Depends(db_session)) -> Any:
    case = cases_repo.get(session, case_id)
    if case is None:
        raise HTTPException(404, "case not found")
    payload = CaseDetail.model_validate(case, from_attributes=True)
    payload.counts = cases_repo.counts(session, case_id)
    return payload


@router.patch("/cases/{case_id}", response_model=CaseOut)
def update_case(
    case_id: str,
    body: CaseUpdate,
    session: Session = Depends(db_session),
    host: HostServices = Depends(host_services),
) -> Any:
    case = cases_repo.get(session, case_id)
    if case is None:
        raise HTTPException(404, "case not found")
    case_service.update_case(session, host, case, **body.model_dump(exclude_unset=True))
    session.commit()
    return case


@router.get("/cases/{case_id}/timeline")
def case_timeline(
    case_id: str,
    limit: int = Query(default=400, le=2000),
    session: Session = Depends(db_session),
) -> list[dict[str, Any]]:
    if cases_repo.get(session, case_id) is None:
        raise HTTPException(404, "case not found")
    return case_service.timeline(session, case_id, limit=limit)
