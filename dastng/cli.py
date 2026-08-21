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


@main.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8810, type=int)
def serve(host: str, port: int) -> None:
    """Start the REST API (Phase 6). Placeholder until the backend lands."""
    console.print("[yellow]serve[/yellow]: REST API arrives in Phase 6 (own backend + UI).")
    console.print(f"would bind {host}:{port}")


if __name__ == "__main__":
    main()
