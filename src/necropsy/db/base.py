"""Declarative base and small column helpers."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Datetimes that are always timezone-aware UTC in Python.

    SQLite does not store tzinfo, so a value written as aware comes back naive.
    Pydantic then serialises it with no offset -- `2026-09-05T13:26:11.419758` --
    and every API consumer has to guess. A browser guesses *local time*, which
    is silently wrong by up to twelve hours on a case timeline.

    Normalising on the way in and out fixes it for every consumer at once, and
    costs nothing on the wire: SQLite stores the same string either way, so no
    migration is needed.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class Base(DeclarativeBase):
    # Applies to every `Mapped[datetime]` column without touching each model.
    type_annotation_map = {datetime: UTCDateTime}


def pk_column() -> Mapped[str]:
    return mapped_column(String(36), primary_key=True, default=new_id)


def ts_column(**kw: object) -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), **kw)  # type: ignore[arg-type]
