"""Engine and session factory.

Necropsy owns its own SQLite file and never writes to the pentest backend's
database. SQLite is single-writer: workers writing finding rows during a long
analysis would contend with the host module's writes and produce
``database is locked`` under exactly the conditions we care about (long
analysis plus a live UI). WAL plus a busy timeout makes our own concurrency
survivable. See docs/ARCHITECTURE.md S4.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from necropsy.config import get_settings
from necropsy.db.base import Base

_engine: Engine | None = None
_factory: sessionmaker[Session] | None = None


def _configure_sqlite(dbapi_conn, _record) -> None:  # type: ignore[no-untyped-def]
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA busy_timeout=5000")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.close()


def make_engine(url: str | None = None) -> Engine:
    url = url or get_settings().db_url
    engine = create_engine(url, future=True, pool_pre_ping=True)
    if engine.dialect.name == "sqlite":
        event.listen(engine, "connect", _configure_sqlite)
    return engine


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = make_engine()
    return _engine


def get_sessionmaker() -> sessionmaker[Session]:
    global _factory
    if _factory is None:
        _factory = sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)
    return _factory


def configure(engine: Engine) -> None:
    """Point the process at a specific engine (tests, CLI, worker bootstrap)."""
    global _engine, _factory
    _engine = engine
    _factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def create_all(engine: Engine | None = None) -> None:
    """Schema straight from the models.

    Alembic is the source of truth for anything holding real case data; this
    exists for tests and first-run bootstrap. ``tests/test_migrations.py``
    asserts the two agree.
    """
    import necropsy.db.models  # noqa: F401  (register mappers)

    Base.metadata.create_all(engine or get_engine())
