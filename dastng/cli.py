"""dast-ng command-line interface."""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import Config
from .orchestrator.workflow import WorkflowRunner, load_workflow

console = Console()


@click.group()
def main() -> None:
    """dast-ng: standalone open-source DAST appliance."""


@main.command()
def version() -> None:
    """Print the version."""
    console.print(f"dast-ng {__version__}")


@main.command()
@click.option("--workflow", "-w", default="core", help="Workflow name (bundled) or path.")
@click.option("--target", "-t", required=True, help="Target base URL.")
@click.option("--session", "-s", "session_path", default=None,
              help="Path to a captured storageState JSON (Phase 1). Omit for unauthenticated.")
@click.option("--allow-active", is_flag=True, default=False,
              help="Authorize active attack traffic for this target (required by active tools).")
@click.option("--dry-run", is_flag=True, default=False, help="Plan only; run no tools.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit machine-readable JSON.")
def launch(workflow: str, target: str, session_path: str | None,
           allow_active: bool, dry_run: bool, as_json: bool) -> None:
    """Run a scanning workflow against a target."""
    Config.from_env()  # loaded for side effects / future DB + egress wiring
    spec = load_workflow(workflow)

    session = None
    if session_path:
        with open(session_path, "r", encoding="utf-8") as fh:
            session = json.load(fh)

    runner = WorkflowRunner(
        spec, allow_active=allow_active, dry_run=dry_run,
        log=(lambda m: None) if as_json else console.print,
    )
    result = runner.run(target, session=session)

    if as_json:
        click.echo(json.dumps({
            "workflow": result.workflow,
            "target": result.target,
            "frontier": result.frontier_stats,
            "findings": result.findings,
            "tools": [{"tool": r.tool, "ok": r.ok, "note": r.note} for r in result.results],
        }, indent=2))
        return

    table = Table(title=f"{result.workflow} vs {result.target}")
    table.add_column("tool")
    table.add_column("status")
    table.add_column("note")
    for r in result.results:
        table.add_row(r.tool, "[green]ok[/green]" if r.ok else "[yellow]skip/err[/yellow]", r.note)
    console.print(table)
    console.print(f"frontier: {result.frontier_stats}")
    console.print(f"findings: {len(result.findings)}")


@main.group()
def auth() -> None:
    """Capture, check, and inspect login sessions."""


@auth.command("capture")
@click.option("--profile", "-p", required=True, help="Auth profile name (bundled) or path.")
@click.option("--base", "-b", default=None, help="Target base URL (or set the profile's base env).")
@click.option("--out", "-o", required=True, help="Where to write the captured session JSON.")
@click.option("--security", default=None, help="DVWA-style security level (low/medium/high).")
@click.option("--interactive", "-i", is_flag=True, default=False,
              help="Headed browser; log in by hand (SSO / push MFA / CAPTCHA), then capture.")
@click.option("--headed", is_flag=True, default=False, help="Run scripted capture with a visible browser.")
def auth_capture(profile: str, base: str | None, out: str, security: str | None,
                 interactive: bool, headed: bool) -> None:
    """Establish and persist a login session (the one-time set)."""
    from .auth.capture import capture_interactive, capture_scripted
    from .auth.profile import load_profile

    prof = load_profile(profile)
    try:
        if interactive:
            session = capture_interactive(prof, base, security=security)
        else:
            session = capture_scripted(prof, base, headless=not headed, security=security)
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc
    session.save(out)
    console.print(f"[green]captured[/green] {session.summary()}")
    console.print(f"saved -> {out}")


@auth.command("check")
@click.option("--session", "-s", "session_path", required=True, help="Captured session JSON.")
@click.option("--profile", "-p", default=None, help="Profile for the validity URL/marker.")
@click.option("--base", "-b", default=None, help="Target base URL.")
@click.option("--url", "-u", default=None, help="Explicit URL to probe (overrides profile).")
@click.option("--marker", "-m", default=None, help="Logged-in marker to assert in the body.")
def auth_check(session_path: str, profile: str | None, base: str | None,
               url: str | None, marker: str | None) -> None:
    """Probe whether a session is still logged in."""
    from .auth.session import Session
    from .auth.validity import is_valid, probe_profile

    session = Session.load(session_path)
    if url:
        ok, note = is_valid(session, url, marker)
    elif profile:
        from .auth.profile import load_profile
        prof = load_profile(profile)
        ok, note = probe_profile(session, prof, prof.resolve_base(base or session.origin))
    else:
        raise click.ClickException("pass --url or --profile to know what to probe")
    tag = "[green]VALID[/green]" if ok else "[red]INVALID[/red]"
    console.print(f"{tag} {note}")
    if not ok:
        raise SystemExit(1)


@auth.command("show")
@click.option("--session", "-s", "session_path", required=True, help="Captured session JSON.")
def auth_show(session_path: str) -> None:
    """Print a summary of a captured session."""
    from .auth.session import Session
    session = Session.load(session_path)
    console.print(session.summary())
    for c in session.cookies:
        console.print(f"  cookie {c.get('name')}={str(c.get('value'))[:12]}... "
                      f"domain={c.get('domain')} path={c.get('path')}")


@main.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8810, type=int)
def serve(host: str, port: int) -> None:
    """Start the REST API (Phase 6). Placeholder until the backend lands."""
    console.print("[yellow]serve[/yellow]: REST API arrives in Phase 6 (own backend + UI).")
    console.print(f"would bind {host}:{port}")


if __name__ == "__main__":
    main()
