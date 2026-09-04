"""Operator CLI.

Everything the GUI panel can do, the CLI can do, because a malware platform you
can only drive through a GUI is one you cannot script a corpus through.
"""

from __future__ import annotations

from pathlib import Path

import typer

from necropsy.config import get_settings

app = typer.Typer(help="Necropsy -- malware analysis module", no_args_is_help=True)
case_app = typer.Typer(help="Case management", no_args_is_help=True)
app.add_typer(case_app, name="case")


@app.command()
def serve(
    port: int | None = typer.Option(None, help="Override NECROPSY_HTTP_PORT"),
    host_addr: str = typer.Option("127.0.0.1", "--host", help="Bind address"),
    create_schema: bool = typer.Option(False, help="Create tables from the models on boot"),
) -> None:
    """Run the standalone API the GUI panel binds to."""
    import uvicorn

    from necropsy.standalone.app import create_app

    settings = get_settings()
    uvicorn.run(create_app(create_schema=create_schema), host=host_addr, port=port or settings.http_port)


@app.command()
def worker(
    queues: list[str] = typer.Option(None, "--queue", "-q", help="Queues to consume"),
    burst: bool = typer.Option(False, help="Exit once the queues are empty"),
) -> None:
    """Run an RQ worker for analysis jobs."""
    from necropsy.jobs.queue import run_worker

    run_worker(list(queues) if queues else None, burst=burst)


@app.command("init-db")
def init_db() -> None:
    """Create the schema from the models (dev bootstrap; Alembic owns real data)."""
    from necropsy.db.session import create_all, get_engine

    create_all()
    typer.echo(f"schema ready at {get_engine().url.render_as_string(hide_password=True)}")


@case_app.command("new")
def case_new(
    name: str,
    tag: list[str] = typer.Option(None, "--tag", "-t"),
    engagement: str | None = typer.Option(None, help="Host engagement reference"),
    allow_ai: bool = typer.Option(
        False,
        "--allow-ai-disclosure",
        help="Permit sample-derived content to be sent to the Claude API (Phase 5)",
    ),
) -> None:
    from necropsy.cases import service as case_service
    from necropsy.db.session import session_scope
    from necropsy.runtime import get_host

    with session_scope() as session:
        case = case_service.create_case(
            session,
            get_host(),
            name=name,
            tags=list(tag) if tag else [],
            host_engagement_ref=engagement,
            ai_disclosure_allowed=allow_ai,
        )
        typer.echo(case.id)


@case_app.command("ls")
def case_ls() -> None:
    from necropsy.db.repos import cases as cases_repo
    from necropsy.db.session import session_scope

    with session_scope() as session:
        for case in cases_repo.list_cases(session):
            counts = cases_repo.counts(session, case.id)
            typer.echo(
                f"{case.id}  {case.status.value:<10} {case.name[:40]:<40} "
                f"samples={counts['samples']} findings={counts['findings']} "
                f"open_actions={counts['open_actions']}"
            )


@app.command()
def ingest(
    path: Path,
    case: str = typer.Option(..., "--case", "-c", help="Case id"),
    note: str | None = typer.Option(None),
    wait: bool = typer.Option(True, help="Run identification inline rather than queueing it"),
) -> None:
    """Ingest a sample into a case."""
    from necropsy.db.session import session_scope
    from necropsy.enums import SampleSource
    from necropsy.intake import service as intake
    from necropsy.jobs.runner import InlineRunner, get_runner
    from necropsy.runtime import get_host

    if not path.is_file():
        raise typer.BadParameter(f"not a readable file: {path}")

    with session_scope() as session:
        result = intake.ingest_file(
            session,
            get_host(),
            case_id=case,
            src=path,
            observed_filename=path.name,
            source=SampleSource.PATH,
            note=note,
        )
        sha = result.sample.sha256
        job_id = result.job_id
        new = result.sample_created
        others = result.other_case_count

    typer.echo(f"sha256   {sha}")
    typer.echo(f"new      {new}")
    if others:
        typer.secho(f"also in  {others} other case(s)", fg=typer.colors.YELLOW)

    if job_id:
        runner = InlineRunner() if wait else get_runner()
        runner.submit(job_id, "identify")
        typer.echo(f"job      {job_id}")


@app.command()
def reindex(limit: int = 1000) -> None:
    """Replay findings the finding sink has not confirmed.

    A no-op until the Phase 4 Elastic sink is configured -- the point is that a
    SIEM outage costs a backfill, never a finding.
    """
    from necropsy.db.repos import findings as findings_repo
    from necropsy.db.session import session_scope
    from necropsy.sinks import get_sink

    sink = get_sink()
    sent = 0
    with session_scope() as session:
        pending = findings_repo.unmirrored(session, limit=limit)
        for finding in pending:
            doc_id = sink.emit(finding)
            if doc_id:
                from necropsy.db.base import utcnow

                finding.elastic_doc_id = doc_id
                finding.mirrored_at = utcnow()
                sent += 1
    typer.echo(f"sink={sink.name} pending={len(pending)} mirrored={sent}")


@app.command()
def doctor() -> None:
    """Report what this install can and cannot do."""
    from necropsy.intake.hashing import have_tlsh
    from necropsy.intake.identify import have_magic

    settings = get_settings()
    typer.echo(f"database        {settings.db_url}")
    typer.echo(f"vault root      {settings.vault_root}")
    typer.echo(f"job runner      {settings.job_runner}")
    typer.echo(f"target arches   {', '.join(settings.target_arches) or '(none)'}")
    typer.echo(f"TLSH            {'yes' if have_tlsh() else 'no  (pip install necropsy[analysis])'}")
    typer.echo(f"libmagic        {'yes' if have_magic() else 'no  (pip install necropsy[analysis])'}")

    import shutil

    typer.echo(f"ssdeep binary   {shutil.which('ssdeep') or 'not found (optional, GPL, shelled out)'}")

    try:
        import redis as redis_lib

        redis_lib.Redis.from_url(settings.redis_url).ping()
        typer.echo("redis           reachable")
    except Exception as exc:  # noqa: BLE001
        typer.secho(f"redis           unreachable ({exc}); use NECROPSY_JOB_RUNNER=inline",
                    fg=typer.colors.YELLOW)

    if not settings.elastic_url:
        typer.echo("elastic         not configured (finding mirror is a no-op until Phase 4)")


if __name__ == "__main__":
    app()
