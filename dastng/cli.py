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
@click.option("--force", is_flag=True, default=False,
              help="Scan even if the session fails its validity probe (not recommended).")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit machine-readable JSON.")
def launch(workflow: str, target: str, session_path: str | None,
           allow_active: bool, dry_run: bool, force: bool, as_json: bool) -> None:
    """Run a scanning workflow against a target."""
    Config.from_env()  # loaded for side effects / future DB + egress wiring
    spec = load_workflow(workflow)

    session = None
    if session_path:
        with open(session_path, "r", encoding="utf-8") as fh:
            session = json.load(fh)
        # Gate: never scan logged-out. If the session fails its validity probe, abort loudly
        # instead of silently producing unauthenticated (garbage) results.
        if not dry_run:
            from .auth.session import Session
            from .auth.validity import is_valid
            sess = Session.from_dict(session)
            marker = sess.meta.get("validity_marker") or "Logout"
            probe_url = sess.meta.get("validity_url") or sess.origin or target
            ok, note = is_valid(sess, probe_url, marker)
            if ok:
                console.print(f"[green]session valid[/green]: {note}")
            elif force:
                console.print(f"[yellow]session INVALID but --force set[/yellow]: {note}")
            else:
                raise click.ClickException(
                    f"session invalid ({note}); refusing to scan logged-out. Re-capture with "
                    f"`dast-ng auth capture` (check credentials), or pass --force to override."
                )

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


# Map result filenames (in a --results dir) to tools.
_RESULT_FILES = {
    "nuclei": ["nuclei.jsonl", "nuclei.json"],
    "dalfox": ["dalfox.json", "dalfox.jsonl"],
    "zap": ["zap.json", "report.json"],
    "sqlmap": ["sqlmap.txt", "sqlmap.log"],
    "commix": ["commix.txt", "commix.log"],
}


@main.command()
@click.option("--oracle", "-O", default="dvwa", help="Ground-truth oracle name (bundled) or path.")
@click.option("--results", "-r", "results_dir", required=True,
              help="Directory of native tool outputs (nuclei.jsonl, dalfox.json, zap.json, ...).")
@click.option("--burp", "burp_path", default=None, help="Burp XML export -> the reference column.")
@click.option("--out", "-o", "out_path", default=None, help="Write the full report JSON here.")
def score(oracle: str, results_dir: str, burp_path: str | None, out_path: str | None) -> None:
    """Score tool outputs against a known-vuln oracle and print a category x tool matrix."""
    import json as _json
    import os

    from .scoring.burp import parse_burp
    from .scoring.normalize import normalize
    from .scoring.oracle import load_oracle
    from .scoring.score import build_matrix, matrix_to_dict, score_columns

    orc = load_oracle(oracle)
    columns: dict[str, list] = {}
    for tool, names in _RESULT_FILES.items():
        for fn in names:
            p = os.path.join(results_dir, fn)
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as fh:
                    columns[tool] = normalize(tool, fh.read())
                break

    if burp_path and os.path.exists(burp_path):
        with open(burp_path, "r", encoding="utf-8") as fh:
            columns["burp"] = parse_burp(fh.read())

    if not columns:
        raise click.ClickException(f"no recognized result files found in {results_dir}")

    scored = score_columns(orc, columns)
    tool_cols = [t for t in ("nuclei", "zap", "sqlmap", "dalfox", "commix") if t in scored]
    order = tool_cols + ["pipeline"] + (["burp"] if "burp" in scored else [])

    rows = build_matrix(orc, scored, order)
    table = Table(title=f"coverage vs {orc.name} (recall by category)")
    table.add_column("category")
    table.add_column("n", justify="right")
    for c in order:
        table.add_column(c, justify="center")
    if "burp" in scored:
        table.add_column("Δ pipe-burp", justify="right")
    for r in rows:
        cells = [r.category, str(r.total)]
        for c in order:
            tp, n = r.recalls.get(c, (0, 0))
            cells.append(f"{tp}/{n}" if n else "-")
        if "burp" in scored:
            d = r.delta
            tag = "" if d is None else (f"[green]+{d}[/green]" if d > 0
                                        else (f"[red]{d}[/red]" if d < 0 else "0"))
            cells.append(tag)
        table.add_row(*cells)
    console.print(table)

    prec = " ".join(f"{c}={scored[c].precision:.2f}" for c in order
                    if scored[c].precision is not None)
    console.print(f"precision (matched/total findings, DVWA caveat): {prec}")

    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            _json.dump(matrix_to_dict(orc, scored, order), fh, indent=2)
        console.print(f"report -> {out_path}")


@main.command()
@click.option("--target", "-t", required=True, help="Base URL (blind: no endpoints supplied).")
@click.option("--session", "-s", "session_path", required=True, help="Captured session JSON.")
@click.option("--depth", default=3, type=int, help="Crawl depth.")
@click.option("--profile", default="normal",
              type=click.Choice(["polite", "normal", "aggressive"]),
              help="Politeness: 'polite' throttles hard for lockout-prone production targets.")
@click.option("--out", "-o", "out_path", default=None, help="Write findings JSON here.")
def engagement(target: str, session_path: str, depth: int, profile: str,
               out_path: str | None) -> None:
    """Blind engagement: crawl -> discover forms/CSRF -> scan (CSRF-aware) -> verify -> report.

    Does NOT know where the vulns are. Active scanning; authorized targets only.
    """
    import json as _json
    from urllib.parse import urlsplit

    from .auth.session import Session
    from .auth.validity import is_valid
    from .engagement import run_engagement

    sess = Session.load(session_path)
    host = urlsplit(target).hostname or ""
    cookie = sess.cookie_header(host)
    ok, note = is_valid(sess, sess.meta.get("validity_url") or target,
                        sess.meta.get("validity_marker") or "Logout")
    if not ok:
        raise click.ClickException(f"session invalid ({note}); re-capture before an engagement.")

    # Pre-flight: prove the parse paths still work against canaries, so a stale parser can't
    # silently under-report on this run.
    from .selftest import run_selftest
    st = run_selftest()
    failed = [r for r in st if not r.passed]
    if failed:
        for r in failed:
            console.print(f"[red]parse self-test FAIL[/red] {r.check}: {r.detail}")
        raise click.ClickException("aborting: a tool/parser self-test failed (see above). "
                                   "Findings could be silently missed. Fix parsers, then re-run.")
    console.print(f"[green]parse self-test: {len(st)} checks healthy[/green]")

    from .updater import stale_components
    stale = stale_components()
    if stale:
        console.print(f"[yellow]stale detection content[/yellow]: {', '.join(stale)} "
                      f"— run `dast-ng update` for freshest templates/rules (or proceed offline).")
    console.print(f"[green]session valid[/green] · crawling {target} blind...")

    result = run_engagement(target, cookie, host, depth=depth, profile=profile)
    console.print(f"crawled {len(result['urls'])} urls · {result['targets']} injection targets")

    table = Table(title=f"blind engagement · {target}")
    table.add_column("category"); table.add_column("tool"); table.add_column("param")
    table.add_column("verified"); table.add_column("evidence")
    for f in result["findings"]:
        v = f["verified"]
        vtag = "[green]CONFIRMED[/green]" if v is True else ("[red]refuted[/red]" if v is False
                                                             else "[dim]tool[/dim]")
        table.add_row(f["category"], f["tool"], str(f["param"]), vtag, (f["evidence"] or "")[:50])
    console.print(table)
    confirmed = sum(1 for f in result["findings"] if f["verified"] is True)
    console.print(f"findings: {len(result['findings'])} ({confirmed} independently verified)")
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            _json.dump(result, fh, indent=2)
        console.print(f"report -> {out_path}")


@main.command()
def selftest() -> None:
    """Verify every tool->parser path against known-vulnerable canaries. Fails loudly if a
    parser has gone stale (e.g. a tool changed its output format), so silent under-reporting
    can't happen. Run before an engagement (the engagement runs it automatically)."""
    from .selftest import run_selftest, selftest_ok
    results = run_selftest()
    for r in results:
        tag = "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]"
        console.print(f"  {tag}  {r.check:<22} {r.detail}")
    if not selftest_ok(results):
        raise click.ClickException("parse self-test FAILED — a parser is stale; fix before scanning.")
    console.print("[green]all parse paths healthy[/green]")


@main.command()
@click.option("--status", is_flag=True, default=False, help="Show freshness only; do not update.")
@click.option("--component", "-c", "components", multiple=True,
              help="Update only these (nuclei-templates/semgrep-rules/retirejs-db/tools).")
def update(status: bool, components: tuple) -> None:
    """Fetch the freshest detection content ONCE (templates, rules, vuln-DB), stamped so
    scans can then run offline/air-gapped. Run this before an engagement."""
    from .updater import freshness_report, update_all

    if status:
        console.print("[bold]detection content freshness[/bold]")
        for line in freshness_report():
            console.print(line)
        return

    console.print("updating detection content (reaching the internet once)...")
    _m, log = update_all(list(components) or None)
    for line in log:
        console.print(f"  [green]OK[/green] {line}")
    console.print("\n[bold]freshness[/bold]")
    for line in freshness_report():
        console.print(line)


@main.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8810, type=int)
def serve(host: str, port: int) -> None:
    """Start the REST API (Phase 6). Placeholder until the backend lands."""
    console.print("[yellow]serve[/yellow]: REST API arrives in Phase 6 (own backend + UI).")
    console.print(f"would bind {host}:{port}")


if __name__ == "__main__":
    main()
