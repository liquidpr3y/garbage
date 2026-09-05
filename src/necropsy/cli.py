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
def triage(
    sha256: str,
    case: str = typer.Option(..., "--case", "-c", help="Case id"),
) -> None:
    """Run static triage on a sample already in a case."""
    from necropsy.db.repos import jobs as jobs_repo, samples as samples_repo
    from necropsy.db.session import session_scope
    from necropsy.enums import JobKind
    from necropsy.jobs.runner import InlineRunner

    with session_scope() as session:
        sample = samples_repo.get_by_sha256(session, sha256.lower())
        if sample is None:
            raise typer.BadParameter(f"no sample with sha256 {sha256}")
        job, _ = jobs_repo.enqueue_or_get(
            session, case_id=case, kind=JobKind.STATIC_TRIAGE,
            sample_id=sample.id, sample_sha256=sample.sha256,
        )
        job_id = job.id

    InlineRunner().submit(job_id, JobKind.STATIC_TRIAGE.value)

    with session_scope() as session:
        from necropsy.db.repos import findings as findings_repo, jobs as jobs_repo2

        done = jobs_repo2.get(session, job_id)
        typer.echo(f"job {job_id} {done.state.value}")
        if done.error:
            typer.secho(done.error.splitlines()[0], fg=typer.colors.RED)
            raise typer.Exit(1)
        for finding in sorted(findings_repo.for_case(session, case), key=lambda f: f.type):
            techniques = ",".join(finding.attack_technique_ids) or "-"
            typer.echo(
                f"  {finding.severity.value:<8} {finding.confidence:<5} "
                f"{finding.type:<42} {techniques}"
            )


@app.command()
def actions(case: str = typer.Option(..., "--case", "-c", help="Case id")) -> None:
    """List the proposals awaiting a decision on a case."""
    from necropsy.db.repos import actions as actions_repo
    from necropsy.db.session import session_scope

    with session_scope() as session:
        for action in actions_repo.for_case(session, case):
            flag = "" if action.available else "  UNAVAILABLE"
            colour = typer.colors.RED if action.risk_score >= 8 else (
                typer.colors.YELLOW if action.risk_score >= 4 else typer.colors.GREEN
            )
            typer.secho(
                f"{action.id}  risk {action.risk_score:>4} {action.risk_band:<9} "
                f"{action.kind:<18} {action.title}{flag}",
                fg=colour,
            )
            if not action.available and action.unavailable_reason:
                typer.echo(f"      {action.unavailable_reason}")


@app.command()
def accept(
    action_id: str,
    note: str | None = typer.Option(None, help="Why you are authorising this"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt"),
) -> None:
    """Authorise a proposal and run its job.

    Detonation is deliberately reachable only this way, never as its own
    command: the acceptance record is what shows a named human authorised
    running live malware, and a direct `necropsy detonate` would bypass it.
    """
    from necropsy.actions.service import ActionRefused
    from necropsy.actions.service import accept as accept_action
    from necropsy.db.repos import actions as actions_repo, jobs as jobs_repo
    from necropsy.db.session import session_scope
    from necropsy.jobs.runner import InlineRunner
    from necropsy.runtime import get_host

    with session_scope() as session:
        action = actions_repo.get(session, action_id)
        if action is None:
            raise typer.BadParameter(f"no action {action_id}")

        if not yes and action.risk_score >= 4:
            typer.secho(f"{action.title}", fg=typer.colors.YELLOW, bold=True)
            typer.echo(f"  risk {action.risk_score} ({action.risk_band})")
            for factor in action.risk_factors:
                sign = "+" if factor["direction"] == 1 else "-"
                typer.echo(f"    {sign}{factor['weight']:<4} {factor['label']}")
            typer.echo(f"  {action.rationale}")
            typer.confirm("Authorise?", abort=True)

        try:
            acceptance = accept_action(session, get_host(), action, note=note)
        except ActionRefused as exc:
            typer.secho(str(exc), fg=typer.colors.RED)
            raise typer.Exit(1) from None
        job_id, kind = acceptance.job_id, acceptance.kind.value

    InlineRunner().submit(job_id, kind)

    with session_scope() as session:
        job = jobs_repo.get(session, job_id)
        typer.echo(f"job {job_id} {job.state.value}")
        if job.error:
            typer.secho(job.error.splitlines()[0], fg=typer.colors.RED)
            raise typer.Exit(1)
        for key, value in (job.result_summary or {}).items():
            typer.echo(f"  {key}: {value}")


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
    """Report what this install can and cannot do.

    Worth running before triaging anything that matters: every line that says
    "no" is a class of finding this machine will silently not produce.
    """
    import shutil

    from necropsy.analysis.ghidra import have_ghidra, headless_binary
    from necropsy.analysis.pe import have_lief
    from necropsy.analysis.rizin import have_rizin, rizin_binary
    from necropsy.analysis.yara_rules import have_yara, rule_files
    from necropsy.intake.hashing import have_tlsh
    from necropsy.intake.identify import have_magic

    settings = get_settings()
    typer.echo(f"database        {settings.db_url}")
    typer.echo(f"vault root      {settings.vault_root}")
    typer.echo(f"job runner      {settings.job_runner}")
    typer.echo(f"target arches   {', '.join(settings.target_arches) or '(none)'}")
    typer.echo("")

    extras = "pip install necropsy[analysis]"
    _line("LIEF (PE detail)", have_lief(), extras)
    _line("YARA", have_yara(), extras)
    _line("TLSH", have_tlsh(), extras)
    _line("libmagic", have_magic(), extras)
    _line("rizin", have_rizin(), "install rizin, or set NECROPSY_RIZIN_PATH",
          rizin_binary() or "")
    _line("Ghidra", have_ghidra(), "set NECROPSY_GHIDRA_HOME to the install root",
          str(headless_binary() or ""))
    _line("ssdeep binary", bool(shutil.which("ssdeep")),
          "optional; GPL, so shelled out rather than linked")

    packaged = sum(1 for _p, is_packaged in rule_files() if is_packaged)
    operator = sum(1 for _p, is_packaged in rule_files() if not is_packaged)
    typer.echo(f"\nYARA rule files {packaged} packaged, {operator} operator-supplied")

    typer.echo("")
    _sandbox_report()

    try:
        import redis as redis_lib

        redis_lib.Redis.from_url(settings.redis_url).ping()
        typer.echo("redis           reachable")
    except Exception as exc:  # noqa: BLE001
        typer.secho(f"redis           unreachable ({exc}); use NECROPSY_JOB_RUNNER=inline",
                    fg=typer.colors.YELLOW)


def _sandbox_report() -> None:
    from necropsy.elastic.client import ElasticClient
    from necropsy.sandbox.targets import NoTargetConfigured, build_target

    settings = get_settings()
    try:
        target = build_target()
        typer.secho(
            f"sandbox          ready  {target.caps.name} {target.caps.arch.value} "
            f"snapshot={target.caps.snapshot}",
            fg=typer.colors.GREEN,
        )
        if not target.caps.supports_egress:
            typer.echo("                 egress runs unavailable (no egress snapshot configured)")
    except NoTargetConfigured as exc:
        typer.secho(f"sandbox          no     ({exc})", fg=typer.colors.YELLOW)
    except Exception as exc:  # noqa: BLE001
        typer.secho(f"sandbox          error  ({exc})", fg=typer.colors.RED)

    _line(
        "pcap capture", bool(settings.sandbox_pcap_interface),
        "set NECROPSY_SANDBOX_PCAP_INTERFACE to a host-only vmnet",
        settings.sandbox_pcap_interface or "",
    )

    elastic = ElasticClient.try_from_settings()
    if elastic is None:
        typer.secho(
            "elastic          no     (NECROPSY_ELASTIC_URL unset; detonations will have "
            "no host telemetry)", fg=typer.colors.YELLOW,
        )
    else:
        try:
            version = elastic.ping().get("version", {}).get("number", "?")
            typer.secho(f"elastic          yes    {version}", fg=typer.colors.GREEN)
        except Exception as exc:  # noqa: BLE001
            typer.secho(f"elastic          no     (unreachable: {exc})", fg=typer.colors.YELLOW)


def _line(label: str, ok: bool, remedy: str, detail: str = "") -> None:
    if ok:
        typer.secho(f"{label:<16} yes  {detail}".rstrip(), fg=typer.colors.GREEN)
    else:
        typer.secho(f"{label:<16} no   ({remedy})", fg=typer.colors.YELLOW)


if __name__ == "__main__":
    app()
