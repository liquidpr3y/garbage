"""Request-scoped dependencies.

Sessions are handed out *without* an implicit commit. Routes commit explicitly,
because job submission must happen after the commit -- a worker opening its own
session cannot see an uncommitted job row.
"""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Header, HTTPException, status
from sqlalchemy.orm import Session

from necropsy.contracts.host import HostServices
from necropsy.db.session import get_sessionmaker
from necropsy.runtime import get_host


def db_session() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


def host_services() -> HostServices:
    return get_host()


def confirm_malware(
    x_necropsy_confirm_malware: str | None = Header(default=None),
) -> None:
    """Small deliberate friction on the one irreversible-ish action.

    Ingest copies bytes into the vault and starts a chain of analysis. Requiring
    an explicit header makes an accidental submission of the wrong file -- a
    client document, a personal photo -- meaningfully harder than a stray drag.
    """
    if (x_necropsy_confirm_malware or "").lower() != "true":
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail=(
                "Set header X-Necropsy-Confirm-Malware: true to confirm this file is "
                "intended for malware analysis and may be copied into the sample vault."
            ),
        )
