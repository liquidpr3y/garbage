"""Alembic and the models must not drift.

create_all() is what tests and first-run bootstrap use; Alembic is what touches
a database holding real case data. If they disagree, the disagreement surfaces
the first time someone upgrades a populated vault -- which is the worst possible
moment to find out.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import inspect

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def alembic_db(tmp_path: Path):  # type: ignore[no-untyped-def]
    alembic = pytest.importorskip("alembic")
    from alembic.config import Config

    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url)

    from alembic import command

    command.upgrade(config, "head")
    return url


def test_migration_matches_the_models(alembic_db: str) -> None:
    from necropsy.db.session import create_all, make_engine

    migrated = inspect(make_engine(alembic_db))
    fresh_engine = make_engine("sqlite:///:memory:")
    create_all(fresh_engine)
    fresh = inspect(fresh_engine)

    migrated_tables = set(migrated.get_table_names()) - {"alembic_version"}
    assert migrated_tables == set(fresh.get_table_names())

    for table in sorted(migrated_tables):
        migrated_cols = {c["name"] for c in migrated.get_columns(table)}
        fresh_cols = {c["name"] for c in fresh.get_columns(table)}
        assert migrated_cols == fresh_cols, f"column drift in {table}"


def test_migration_head_matches_the_module_descriptor() -> None:
    from necropsy.plugin import MODULE

    versions = list((ROOT / "migrations" / "versions").glob("*.py"))
    assert any(MODULE.migration_head in v.name for v in versions)


def test_attack_columns_exist_before_phase_4(alembic_db: str) -> None:
    """Adding these after three phases of findings is the expensive version."""
    from necropsy.db.session import make_engine

    columns = {c["name"] for c in inspect(make_engine(alembic_db)).get_columns("findings")}
    assert {"attack_json", "kill_chain_phase", "elastic_doc_id", "mirrored_at"} <= columns
