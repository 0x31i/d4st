"""d4st command-line interface."""

from __future__ import annotations

import json
import os
import re

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import Config
from .orchestrator.workflow import WorkflowRunner, load_workflow

console = Console()


@click.group()
def main() -> None:
    """d4st: standalone open-source DAST appliance."""
    # Cosmetic startup banner — stderr-only + TTY-gated, so it never touches
    # stdout/JSON/reports (see d4st/art.py). No-op in pipelines and CI.
    from .art import banner
    banner()


@main.command()
def version() -> None:
    """Print the version."""
    console.print(f"d4st {__version__}")


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
                    f"`d4st auth capture` (check credentials), or pass --force to override."
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
@click.option("--username", "-u", default=None, help="Login username (overrides profile/env creds).")
@click.option("--password", "-w", default=None,
              help="Login password (overrides profile/env creds). NOTE: visible in shell history/ps — "
                   "prefer the profile's *_env vars for anything you want to keep secret.")
def auth_capture(profile: str, base: str | None, out: str, security: str | None,
                 interactive: bool, headed: bool, username: str | None, password: str | None) -> None:
    """Establish and persist a login session (the one-time set)."""
    from .auth.capture import capture_interactive, capture_scripted
    from .auth.profile import load_profile

    prof = load_profile(profile)
    try:
        if interactive:
            session = capture_interactive(prof, base, security=security)
        else:
            session = capture_scripted(prof, base, headless=not headed, security=security,
                                       username=username, password=password)
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc
    session.save(out)
    console.print(f"[green]captured[/green] {session.summary()}")
    console.print(f"saved -> {out}")


@auth.command("init")
@click.argument("login_url")
@click.option("--name", "-n", default=None, help="Profile name (default: the target host).")
@click.option("--base", "-b", default=None, help="Base URL (default: the login URL's origin).")
@click.option("--out", "-o", default=None, help="Where to write the profile YAML "
              "(default: d4st/auth/profiles/<name>.yaml).")
@click.option("--session", "-s", "session_out", default=None,
              help="Also save the captured session here (default: sessions/<name>.json).")
def auth_init(login_url: str, name: str | None, base: str | None, out: str | None,
              session_out: str | None) -> None:
    """Record-to-configure: open a browser, LOG IN ONCE, and d4st auto-writes the auth profile.

    Watches which fields you type in and the button you click, detects the bearer token by diffing
    storage, and generates a ready profile — no hand-writing CSS selectors. Needs a display (run it
    locally, not on a headless box).
    """
    import yaml
    from urllib.parse import urlsplit

    from .auth.recorder import record_login

    nm = name or re.sub(r"[^a-z0-9]+", "", (urlsplit(login_url).hostname or "site").split(".")[0].lower()) or "site"
    try:
        profile, session = record_login(login_url, nm, base)
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(f"login recording failed: {exc}") from exc

    out = out or os.path.join("d4st", "auth", "profiles", f"{nm}.yaml")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        yaml.safe_dump(profile, fh, sort_keys=False)
    console.print(f"[green]profile written[/green] -> {out}")
    console.print(f"  username_selector: {profile['username_selector']}")
    console.print(f"  password_selector: {profile['password_selector']}")
    console.print(f"  submit_selector:   {profile['submit_selector']}")
    if profile.get("token"):
        console.print(f"  token:             {profile['token']['key']} "
                      f"({profile['token']['storage']}Storage → {profile['token']['header']})")
    else:
        console.print("  token:             none detected (cookie-session app)")
    console.print(f"  creds via env:     {profile['username_env']} / {profile['password_env']}")

    session_out = session_out or os.path.join("sessions", f"{nm}.json")
    os.makedirs(os.path.dirname(session_out) or ".", exist_ok=True)
    session.save(session_out)
    console.print(f"[green]session captured[/green] -> {session_out}")
    console.print(f"[dim]next: set {profile['username_env']}/{profile['password_env']}, then "
                  f"`d4st run` with an engagement.yaml pointing auth.profile at {out}[/dim]")


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
@click.option("--profile", default="engagement",
              type=click.Choice(["engagement", "safe-deep", "production-safe", "passive-only",
                                 "staging", "aggressive", "polite", "normal"]),
              help="Scan policy. DEFAULT 'engagement': a normal-engagement posture that finishes "
                   "in hours, not days — full depth (full tool roster + payload corpus + "
                   "convergence discovery) and the full safe contract (no data mutation, no "
                   "destructive/auth endpoints, non-corrupting sqlmap, in-network OAST, adaptive "
                   "halt on target stress), sped up by BOUNDED parallelism. Use 'safe-deep' for "
                   "fragile/legacy targets (same depth, gentle single-stream throttle). Others "
                   "are narrower overrides.")
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
    # token-in-sessionStorage SPAs (bearer auth) can only be validated by a rendered browser
    # probe — a raw GET sees the logged-out shell. render when the session carries sessionStorage.
    ok, note = is_valid(sess, sess.meta.get("validity_url") or target,
                        sess.meta.get("validity_marker") or "Logout",
                        render=bool(sess.session_storage))
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
                      f"— run `d4st update` for freshest templates/rules (or proceed offline).")
    if profile in ("production-safe", "passive-only"):
        console.print(f"[cyan]safety policy[/cyan]: [bold]{profile}[/bold] — throttled, "
                      f"{'no attack traffic' if profile == 'passive-only' else 'no data mutation / no destructive endpoints / safe sqlmap'}")
    console.print(f"[green]session valid[/green] · crawling {target} blind...")
    from .art import phase
    phase("CRAWLER", f"authenticated · mapping {host or target} · depth {depth}", "crawl")

    # Token-auth SPA (bearer JWT in sessionStorage): the token is short-lived (APP ~30 min), so a
    # long scan must re-mint it or it silently 401s mid-run. Wire a refresh that re-logs-in via the
    # captured profile (creds from its *_env vars, e.g. APP_USERNAME/APP_PASSWORD) and returns the
    # fresh token; run_engagement calls it before each heavy stage.
    jwt_refresh = None
    if sess.session_storage and sess.meta.get("profile"):
        try:
            from .auth.profile import load_profile
            from .auth.capture import capture_scripted
            _prof = load_profile(sess.meta["profile"])
            _tkey = (_prof.token or {}).get("key")
            if _tkey:
                _base = f"{urlsplit(target).scheme}://{host}"

                def _jwt_refresh() -> str:
                    fresh = capture_scripted(_prof, _base)
                    return fresh.session_storage.get(_tkey, "") or ""
                jwt_refresh = _jwt_refresh
                console.print("[green]JWT refresh armed[/green] (re-login on token expiry; "
                              "needs the profile's cred env vars set)")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]JWT refresh unavailable[/yellow]: {exc}")

    result = run_engagement(target, cookie, host, depth=depth, profile=profile,
                            auth_headers=sess.headers, jwt_refresh=jwt_refresh, session=sess)
    console.print(f"crawled {len(result['urls'])} urls · {result['targets']} injection targets")
    pol = result.get("policy", {})
    if pol:
        console.print(f"[dim]policy {pol['name']}: active={pol['active_scan']} "
                      f"fuzz_forms={pol['fuzz_forms']} sqlmap[{pol['sqlmap']}] · "
                      f"{pol['state_changing_endpoints_skipped']} destructive endpoint(s) skipped[/dim]")

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

    # Auto-ingest into the observability store (console spine). Additive, non-fatal:
    # a store hiccup must never fail a scan. Opt out with D4ST_NO_INGEST=1.
    if not os.environ.get("D4ST_NO_INGEST"):
        try:
            from . import store
            sid = _scan_id_for(out_path, target)
            summ = store.ingest(result, sid)
            console.print(f"[dim]ingested -> {store.db_path()} as '{sid}' "
                          f"({summ['findings']} findings, {summ['exchanges']} exchanges)[/dim]")
        except Exception as e:  # noqa: BLE001
            console.print(f"[yellow]store ingest skipped[/yellow]: {e}")


def _normalize_target(raw: str) -> str:
    """Accept a bare domain ('example.com'), host:port, or full URL and return a base URL.
    Prefers https and falls back to http only if https is unreachable, so `d4st unauth example.com`
    just works."""
    from urllib.parse import urlsplit
    raw = raw.strip().rstrip("/")
    if "://" in raw:
        return raw
    # bare domain / host[:port] — probe https, fall back to http
    import httpx
    for scheme in ("https", "http"):
        base = f"{scheme}://{raw}"
        try:
            httpx.head(base, verify=False, follow_redirects=True, timeout=8)
            return base
        except Exception:  # noqa: BLE001
            continue
    return f"https://{raw}"  # default; the crawler will report if it's truly unreachable


@main.command()
@click.argument("target")
@click.option("--depth", default=4, type=int, show_default=True,
              help="Crawl depth. Deep by default; --fast lowers it.")
@click.option("--fast", is_flag=True, default=False,
              help="Quicker sweep: shallower crawl (depth 2) and a gentler roster. Depth unchanged "
                   "otherwise — this only trades breadth for speed.")
@click.option("--profile", default="engagement",
              type=click.Choice(["engagement", "safe-deep", "production-safe", "passive-only",
                                 "aggressive", "polite", "normal"]),
              help="Safety policy (pace + attack contract), independent of depth. DEFAULT "
                   "'engagement'. Use 'safe-deep' for fragile targets, 'passive-only' for recon-only.")
@click.option("--out", "-o", "out_path", default=None,
              help="Findings JSON path. Default: ./d4st-unauth-<host>.json")
@click.option("--report/--no-report", "want_report", default=True, show_default=True,
              help="Also write a client-grade HTML report next to the JSON.")
def unauth(target: str, depth: int, fast: bool, profile: str, out_path: str | None,
           want_report: bool) -> None:
    """Deep UNAUTHENTICATED scan of a domain — the external-attacker viewpoint, authorized targets only.

    One command, no login, no config: crawl + content discovery + JS route mining + historical URLs,
    then the full unauth roster (nuclei, ZAP active, XSS, SQLi/cmd injection, LFI/RFI, open-redirect,
    CORS reflection, host-header injection, verb tampering, TLS hygiene, JS secret disclosure, and the
    header/config passive checks) — every finding carrying a real request/response + curl repro.

    Pairs with Burp: a second, open-source-tooled viewpoint that digs where a manual pass might not.

        d4st unauth example.com
        d4st unauth https://app.example.com:8443 --profile safe-deep
        d4st unauth example.com --fast -o /tmp/ex.json
    """
    import json as _json
    from urllib.parse import urlsplit

    from .engagement import run_engagement

    base = _normalize_target(target)
    host = urlsplit(base).hostname or ""
    # Keep the unauth sweep bounded so it always completes in a predictable window (the deep
    # engagement's default nuclei budget is an hour — too long for a one-command scan). Operators
    # can still override D4ST_NUCLEI_TIMEOUT. --fast additionally trims the heavy CVE/takeover
    # template corpus to the high-signal exposures/misconfig set.
    if fast:
        depth = min(depth, 2)
        os.environ.setdefault("D4ST_NUCLEI_FAST", "1")
        os.environ.setdefault("D4ST_NUCLEI_TIMEOUT", "240")
    else:
        os.environ.setdefault("D4ST_NUCLEI_TIMEOUT", "900")

    # parse self-test (a stale parser silently under-reports) — warn, do not block an unauth sweep
    try:
        from .selftest import run_selftest
        st = run_selftest()
        bad = [r for r in st if not r.passed]
        if bad:
            for r in bad:
                console.print(f"[yellow]parser self-test warn[/yellow] {r.check}: {r.detail}")
        else:
            console.print(f"[green]parser self-test: {len(st)} checks healthy[/green]")
    except Exception as e:  # noqa: BLE001
        console.print(f"[yellow]self-test skipped[/yellow]: {e}")

    console.print(f"[bold]d4st unauth[/bold] · {base} · depth {depth} · profile [cyan]{profile}[/cyan] "
                  f"· [dim]external / unauthenticated viewpoint[/dim]")
    console.print("[dim]no session — auth-only stages (JWT forgery, WebSocket auth, BOLA) self-skip; "
                  "CORS / host-header / verb-tampering run unauthenticated[/dim]")

    from .art import phase
    phase("CRAWLER", f"mapping {host or base} · depth {depth}", "crawl")

    # unauth: empty cookie, no session, but run the unauth-safe depth suite
    result = run_engagement(base, "", host, depth=depth, profile=profile,
                            auth_headers={}, session=None, unauth_deep=True)

    console.print(f"crawled {len(result['urls'])} urls · {result['targets']} injection targets")
    table = Table(title=f"unauth scan · {base}")
    table.add_column("category"); table.add_column("tool"); table.add_column("url")
    table.add_column("verified"); table.add_column("evidence")
    for f in sorted(result["findings"], key=lambda x: str(x.get("category"))):
        v = f["verified"]
        vtag = "[green]CONFIRMED[/green]" if v is True else ("[red]refuted[/red]" if v is False
                                                             else "[dim]tool[/dim]")
        table.add_row(f["category"], f["tool"], (f.get("url") or "")[:44], vtag,
                      (f["evidence"] or "")[:44])
    console.print(table)
    confirmed = sum(1 for f in result["findings"] if f["verified"] is True)
    console.print(f"findings: {len(result['findings'])} ({confirmed} independently verified)")

    out_path = out_path or f"d4st-unauth-{host or 'target'}.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        _json.dump(result, fh, indent=2)
    console.print(f"findings JSON -> {out_path}")

    if want_report:
        from .art import phase
        phase("REPORTER", "writing the client-grade report", "report")
        from .report import build_report
        rep_path = os.path.splitext(out_path)[0] + ".html"
        html = build_report(result, target=base, meta={"scope": f"{host} (unauthenticated, external)"})
        with open(rep_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        console.print(f"HTML report  -> {rep_path}")

    if not os.environ.get("D4ST_NO_INGEST"):
        try:
            from . import store
            sid = _scan_id_for(out_path, base)
            summ = store.ingest(result, sid)
            console.print(f"[dim]ingested -> {store.db_path()} as '{sid}' "
                          f"({summ['findings']} findings)[/dim]")
        except Exception as e:  # noqa: BLE001
            console.print(f"[yellow]store ingest skipped[/yellow]: {e}")


def _ensure_session(auth: dict, target: str) -> str:
    """Capture a fresh session from the auth profile+creds (or reuse a still-valid stored one).
    Returns the session file path. This is the auto-glue that removes the manual `auth capture` step."""
    from urllib.parse import urlsplit

    from .auth.capture import capture_interactive, capture_scripted
    from .auth.profile import load_profile
    from .auth.session import Session
    from .auth.validity import is_valid

    sess_path = auth["session"]
    base = f"{urlsplit(target).scheme}://{urlsplit(target).hostname}"
    # reuse a fresh existing session if allowed (skips a slow browser login)
    if auth.get("reuse_if_fresh") and os.path.exists(sess_path):
        try:
            s = Session.load(sess_path)
            ok, _ = is_valid(s, s.meta.get("validity_url") or target,
                             s.meta.get("validity_marker") or "Logout",
                             render=bool(s.session_storage))
            if ok:
                console.print(f"[green]reusing valid session[/green] {sess_path}")
                return sess_path
        except Exception:  # noqa: BLE001
            pass
    if not auth.get("profile"):
        raise click.ClickException(f"no valid session at {sess_path} and no auth.profile to capture one")
    prof = load_profile(auth["profile"])
    from .art import phase
    phase("LOGIN", "capturing a real browser session", "session")
    console.print(f"[cyan]capturing session[/cyan] via {auth['profile']} → {sess_path}")
    if auth.get("interactive"):
        s = capture_interactive(prof, base)
    else:
        s = capture_scripted(prof, base, username=auth.get("username"), password=auth.get("password"))
    os.makedirs(os.path.dirname(sess_path) or ".", exist_ok=True)
    s.save(sess_path)
    console.print(f"[green]captured[/green] {s.summary()}")
    return sess_path


@main.command()
@click.argument("config_path", type=click.Path(exists=True))
@click.option("--preflight-only", is_flag=True, default=False,
              help="Resolve config + capture session + print the readiness checklist, then stop.")
def run(config_path: str, preflight_only: bool) -> None:
    """Run a full engagement from a single engagement.yaml — the easy button for a new target.

    Auto-captures the session from the declared auth profile+creds, exports every D4ST_* tuning knob
    from the config (no hand-set env vars), wires the second account for the BOLA matrix if present,
    then scans. `d4st run --preflight-only` stops after the readiness check.
    """
    from . import engagement_config as ec

    cfg = ec.load(config_path)
    applied = ec.apply_env(cfg)
    console.print(f"[bold]engagement[/bold] {cfg['client']} → {cfg['target']}  "
                  f"[dim](profile {cfg['profile']}, scope {', '.join(cfg['scope'])})[/dim]")
    for k, v in applied.items():
        console.print(f"  [dim]{k}={v}[/dim]")

    session_path = _ensure_session(cfg["auth"], cfg["target"])
    if cfg["auth"].get("second"):
        sb = _ensure_session(cfg["auth"]["second"], cfg["target"])
        os.environ["D4ST_AUTHZ_SESSION_B"] = os.path.abspath(sb)
        console.print(f"[green]two-account BOLA matrix armed[/green] (2nd session {sb})")

    if preflight_only:
        console.print("[green]preflight OK[/green] — config resolved, session captured, env exported. "
                      "Drop --preflight-only to scan.")
        return

    # hand off to the existing, fully-wired engagement flow (JWT refresh, keeper, ingest all intact)
    engagement.callback(target=cfg["target"], session_path=session_path, depth=cfg["depth"],
                        profile=cfg["profile"], out_path=cfg["output"])


@main.command("init-config")
@click.option("--out", "-o", default="engagement.yaml", help="Where to write the template.")
def init_config(out: str) -> None:
    """Write a commented engagement.yaml template to fill in for a new target."""
    from . import engagement_config as ec
    if os.path.exists(out):
        raise click.ClickException(f"{out} already exists — refusing to overwrite")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(ec.EXAMPLE)
    console.print(f"[green]wrote[/green] {out} — edit it, then run: d4st run {out}")


@main.command("init")
@click.option("--client", prompt="Client name", help="Client label for the report + file slugs.")
@click.option("--target", prompt="Target base URL", help="e.g. https://app.example.com")
@click.option("--login-url", default=None, help="Login page URL (default: <target>/login).")
@click.option("--profile", "scan_profile", default="engagement", help="Scan policy.")
@click.option("--record/--no-record", default=True,
              help="Open a browser and record the login now to auto-generate the auth profile.")
@click.option("--auth-profile", default=None,
              help="Use an EXISTING auth profile instead of recording (path or bundled name).")
@click.option("--out", "-o", default="engagement.yaml", help="Where to write the engagement config.")
def init(client: str, target: str, login_url: str | None, scan_profile: str,
         record: bool, auth_profile: str | None, out: str) -> None:
    """Guided onboarding: record the login (or point at a profile), then write a ready
    engagement.yaml. New target → scanning in one flow.  Afterwards:  d4st run <out>."""
    import re as _re
    from urllib.parse import urlsplit

    import yaml

    if os.path.exists(out):
        raise click.ClickException(f"{out} already exists — refusing to overwrite")
    host = urlsplit(target).hostname or ""
    if not host:
        raise click.ClickException(f"target is not a valid URL: {target!r}")
    slug = _re.sub(r"[^a-z0-9]+", "", host.split(".")[0].lower()) or "site"

    # Smart pre-flight: fingerprint the app so we can guide the operator (SPA vs classic,
    # headless crawl, likely login) and auto-locate the login page instead of guessing /login.
    login_guess = None
    try:
        from .fingerprint import fingerprint_target
        ap = fingerprint_target(target, host)
        console.print(f"[cyan]detected[/cyan]: {ap.summary()}")
        for seed in ap.entry_seeds:
            if _re.search(r"login|signin|sign-in|auth|account", seed, _re.IGNORECASE):
                login_guess = seed
                break
    except Exception as exc:  # noqa: BLE001
        console.print(f"[dim]fingerprint skipped ({exc}) — proceeding[/dim]")

    if record and not auth_profile:
        from .auth.recorder import record_login
        lu = login_url or login_guess or target.rstrip("/") + "/login"
        if login_guess and not login_url:
            console.print(f"[green]login page auto-detected[/green]: {lu}")
        console.print(f"[cyan]recording login[/cyan] at {lu} — a browser will open; log in once.")
        try:
            profile, session = record_login(lu, slug, f"{urlsplit(target).scheme}://{host}")
        except Exception as exc:  # noqa: BLE001
            raise click.ClickException(f"login recording failed: {exc}") from exc
        auth_profile = os.path.join("d4st", "auth", "profiles", f"{slug}.yaml")
        os.makedirs(os.path.dirname(auth_profile), exist_ok=True)
        with open(auth_profile, "w", encoding="utf-8") as fh:
            yaml.safe_dump(profile, fh, sort_keys=False)
        sp = os.path.join("sessions", f"{slug}.json")
        os.makedirs("sessions", exist_ok=True)
        session.save(sp)
        console.print(f"[green]auth profile[/green] -> {auth_profile}  ·  [green]session[/green] -> {sp}")
        user_env, pass_env = profile["username_env"], profile["password_env"]
    else:
        if not auth_profile:
            raise click.ClickException("either --record or --auth-profile is required")
        user_env, pass_env = f"{slug.upper()}_USERNAME", f"{slug.upper()}_PASSWORD"

    cfg = {
        "client": client, "target": target, "scope": [host], "profile": scan_profile, "depth": 3,
        "output": f"results/{slug}.json",
        "auth": {"profile": auth_profile, "username_env": user_env, "password_env": pass_env,
                 "session": f"sessions/{slug}.json", "reuse_if_fresh": True},
        "tuning": {"full_capture": True, "js_max": 8000, "secret_validate": False,
                   "method_tamper_writes": False},
        "egress": {"verify_ips": "auto"},
        "report": {"client": client, "ref": ""},
    }
    with open(out, "w", encoding="utf-8") as fh:
        yaml.safe_dump(cfg, fh, sort_keys=False)
    console.print(f"[green]wrote engagement config[/green] -> {out}")
    console.print(f"[dim]next: export {user_env}/{pass_env}, then:  d4st run {out}"
                  f"   (or dry-check:  d4st run {out} --preflight-only)[/dim]")


@main.command()
@click.option("--target", "-t", default=None,
              help="Also probe this URL for reachability + app fingerprint.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Machine-readable JSON.")
def doctor(target: str | None, as_json: bool) -> None:
    """Health-check the install before you scan: Python, browser, the scanner roster,
    detection-content freshness, and (with -t) whether a target is reachable.

    Run this FIRST when a scan misbehaves — it tells you exactly what's missing and how
    to fix it, no guessing.

        d4st doctor
        d4st doctor -t https://app.example.com
    """
    import platform
    import sys as _sys
    from urllib.parse import urlsplit

    if as_json:
        os.environ["D4ST_JSON"] = "1"  # also mutes art

    checks: list[dict] = []

    def add(name: str, status: str, detail: str, hint: str = "") -> None:
        checks.append({"check": name, "status": status, "detail": detail, "hint": hint})

    # 1. Python
    v = _sys.version_info
    add("python", "ok" if v >= (3, 9) else "fail", platform.python_version(),
        "" if v >= (3, 9) else "d4st needs Python >= 3.9")

    # 2. Headless browser (Playwright + Chromium) — auth capture needs it
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        browsers = os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or \
            os.path.expanduser("~/.cache/ms-playwright")
        has_chromium = os.path.isdir(browsers) and any(
            n.startswith("chromium") for n in (os.listdir(browsers) if os.path.isdir(browsers) else []))
        add("browser (playwright)", "ok" if has_chromium else "warn",
            "chromium installed" if has_chromium else "playwright present, chromium not found",
            "" if has_chromium else "run: python -m playwright install chromium")
    except Exception:  # noqa: BLE001
        add("browser (playwright)", "warn", "playwright not importable",
            "pip install playwright && python -m playwright install chromium (needed only for authenticated scans)")

    # 3. Scanner roster on PATH
    from .selftest import roster_presence
    rp = roster_presence()
    present = [r.tool for r in rp if r.passed]
    missing = [r.tool for r in rp if not r.passed]
    r_status = "ok" if not missing else ("warn" if len(present) >= len(rp) // 2 else "fail")
    add("scanners", r_status, f"{len(present)}/{len(rp)} on PATH"
        + (f" · missing: {', '.join(missing)}" if missing else ""),
        "" if not missing else "the Docker image ships the full roster; on a bare host, d4st still "
        "runs but silently skips missing tools")

    # 4. Detection-content freshness
    try:
        from .updater import freshness_report
        stale = freshness_report()
        add("detection content", "ok" if not stale else "warn",
            "fresh" if not stale else "; ".join(stale), "" if not stale else "run: d4st update")
    except Exception as e:  # noqa: BLE001
        add("detection content", "warn", f"could not check ({e})", "run: d4st update")

    # 5. Optional target reachability + fingerprint
    if target:
        base = _normalize_target(target)
        host = urlsplit(base).hostname or ""
        try:
            from .fingerprint import fingerprint_target
            ap = fingerprint_target(base, host)
            add("target reachable", "ok", f"{base} · {ap.summary()}")
        except Exception as e:  # noqa: BLE001
            add("target reachable", "fail", f"{base}: {e}",
                "check DNS + routing from THIS host to the target (the scanner must reach it directly)")

    worst = "ok"
    for c in checks:
        if c["status"] == "fail":
            worst = "fail"; break
        if c["status"] == "warn":
            worst = "warn"

    if as_json:
        console.print_json(data={"verdict": worst, "checks": checks})
        return

    from .art import phase
    phase("DOCTOR", "checking your install", "verify")
    tbl = Table(title="d4st doctor")
    tbl.add_column("check"); tbl.add_column("status"); tbl.add_column("detail"); tbl.add_column("fix")
    ico = {"ok": "[green]✓ ok[/green]", "warn": "[yellow]! warn[/yellow]", "fail": "[red]✗ fail[/red]"}
    for c in checks:
        tbl.add_row(c["check"], ico[c["status"]], c["detail"], f"[dim]{c['hint']}[/dim]" if c["hint"] else "")
    console.print(tbl)
    verdict = {"ok": "[green]ready to scan[/green]", "warn": "[yellow]usable — see warnings above[/yellow]",
               "fail": "[red]not ready — fix the failures above[/red]"}[worst]
    console.print(f"verdict: {verdict}")
    if worst != "fail":
        console.print("[dim]next:  d4st detect <url>   (fingerprint + recommended command)   ·   "
                      "d4st unauth <domain>   (one-command external scan)[/dim]")


@main.command()
@click.argument("target")
@click.option("--json", "as_json", is_flag=True, default=False, help="Machine-readable JSON.")
def detect(target: str, as_json: bool) -> None:
    """Fingerprint a target and tell you exactly how to scan it — no scan, no side effects.

    Probes the app, identifies its type (SPA / classic / API) and stack, and prints the
    recommended next command. The 'what do I run?' answer for anyone new to d4st.

        d4st detect app.example.com
    """
    from urllib.parse import urlsplit

    if as_json:
        os.environ["D4ST_JSON"] = "1"
    base = _normalize_target(target)
    host = urlsplit(base).hostname or ""
    from .fingerprint import fingerprint_target
    try:
        ap = fingerprint_target(base, host)
    except Exception as e:
        raise click.ClickException(f"could not reach {base}: {e} — is it up + reachable from here?") from e

    authy = ap.app_type in ("spa", "api") or any(
        "login" in s.lower() or "auth" in s.lower() for s in (ap.signals or []))
    if authy:
        rec = [f"d4st init --client <name> --target {base}", "  # guided: records the login once,",
               "  # writes engagement.yaml, then:  d4st run engagement.yaml"]
        why = "looks authenticated (SPA/API or a login was detected) — an authed scan sees far more"
    else:
        rec = [f"d4st unauth {host or base}"]
        why = "no login detected — a one-command unauthenticated sweep fits"

    if as_json:
        console.print_json(data={"target": base, "app_type": ap.app_type, "tech": ap.tech,
                                 "headless": ap.headless, "signals": ap.signals,
                                 "entry_seeds": ap.entry_seeds, "authenticated_recommended": authy,
                                 "recommended": rec})
        return

    from .art import phase
    phase("SCOUT", f"fingerprinting {host or base}", "discover")
    tbl = Table(title=f"detect · {base}")
    tbl.add_column("property"); tbl.add_column("value")
    tbl.add_row("app type", f"[cyan]{ap.app_type}[/cyan]")
    tbl.add_row("stack", ", ".join(ap.tech) or "[dim]generic[/dim]")
    tbl.add_row("crawl mode", "headless (JS-rendered)" if ap.headless else "plain HTTP")
    tbl.add_row("links seen", str(ap.seed_link_count))
    if ap.entry_seeds:
        tbl.add_row("entry seeds", f"{len(ap.entry_seeds)} discovered")
    for s in (ap.signals or [])[:6]:
        tbl.add_row("signal", f"[dim]{s}[/dim]")
    console.print(tbl)
    console.print(f"[bold]recommended[/bold] — [dim]{why}[/dim]")
    for line in rec:
        console.print(f"  [green]{line}[/green]" if not line.strip().startswith("#") else f"  [dim]{line}[/dim]")


def _scan_id_for(out_path: str | None, target: str) -> str:
    """Stable scan id: the -o filename stem if given, else a slug of the target host."""
    from urllib.parse import urlsplit
    if out_path:
        return os.path.splitext(os.path.basename(out_path))[0]
    host = urlsplit(target).hostname or target or "scan"
    return re.sub(r"[^A-Za-z0-9._-]+", "-", host).strip("-") or "scan"


@main.command()
@click.argument("json_files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--id", "scan_id", default=None,
              help="Scan id to store under (single-file only; default = filename stem).")
@click.option("--db", "db_path_opt", default=None, help="SQLite path (default ~/.d4st/d4st.db).")
def ingest(json_files: tuple, scan_id: str | None, db_path_opt: str | None) -> None:
    """Load one or more engagement result JSONs into the observability store (SQLite).

    Idempotent: re-ingesting a scan id replaces its rows and carries analyst triage/notes
    forward. Use this to backfill existing result files into the console DB.
    """
    from . import store
    if scan_id and len(json_files) > 1:
        raise click.ClickException("--id is only valid with a single file.")
    con = store.connect(db_path_opt)
    store.init_schema(con)
    total = 0
    for jf in json_files:
        try:
            with open(jf, encoding="utf-8") as fh:
                result = json.loads(fh.read())
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]skip[/red] {jf}: {e}")
            continue
        if "findings" not in result:
            console.print(f"[yellow]skip[/yellow] {jf}: not an engagement result (no findings)")
            continue
        sid = scan_id or os.path.splitext(os.path.basename(jf))[0]
        mtime = int(os.path.getmtime(jf))
        summ = store.ingest(result, sid, con=con, created_at=mtime)
        sv = summ["severities"]
        console.print(f"[green]ingested[/green] {sid}: {summ['findings']} findings "
                      f"({sv['critical']}c/{sv['high']}h/{sv['medium']}m/{sv['low']}l/{sv['info']}i) "
                      f"· {summ['exchanges']} exchanges · {summ['urls']} urls · {summ['engines']} engines"
                      + (f" · carried {summ['carried_forward']} triage" if summ['carried_forward'] else ""))
        total += 1
    con.close()
    console.print(f"[bold]{total} scan(s) in {store.db_path(db_path_opt)}[/bold]")


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
@click.argument("source")
@click.option("--out", "-o", default="d4st_report.html", help="Output HTML report path.")
@click.option("--target", "-t", default="", help="Target URL/host label.")
@click.option("--client", default=None, help="Client / organisation name (cover page).")
@click.option("--scope", default=None, help="Scope description (cover page).")
@click.option("--window", default=None, help="Assessment window, e.g. '2026-08-14 -> 2026-08-15'.")
@click.option("--prepared-by", "prepared_by", default=None, help="Preparer / firm (cover page).")
@click.option("--ref", default=None, help="Engagement reference id.")
@click.option("--logo", default=None, help="Logo path or data-URI for the cover.")
@click.option("--when", default=None, help="Report date string (cover/footer).")
@click.option("--from-db", "from_db", is_flag=True, default=False,
              help="Treat SOURCE as a scan id in the SQLite store instead of a JSON path.")
@click.option("--concise", is_flag=True, default=False,
              help="Cap giant response bodies / raw output on medium/low/info findings "
                   "(critical & high keep full evidence).")
@click.option("--format", "fmt", default="auto",
              help="Report format(s): comma list of html,xlsx,csv,pdf (or 'all'). Default 'auto' "
                   "= infer from the --out extension. Files share the --out basename.")
@click.option("--open", "open_it", is_flag=True, default=False, help="Open the report after writing.")
def report(source: str, out: str, target: str, client: str | None, scope: str | None,
           window: str | None, prepared_by: str | None, ref: str | None, logo: str | None,
           when: str | None, from_db: bool, concise: bool, fmt: str, open_it: bool) -> None:
    """Render a client-grade HTML report from a scan result JSON (or a store scan id with
    --from-db). Light, print/PDF-ready (Cmd-P -> Save as PDF): cover page, executive summary,
    scope & methodology, findings index, MAX-DETAIL findings with full request/response
    evidence, and an appendix. No grade."""
    import json as _json

    from .report import build_report
    if from_db:
        from . import store
        con = store.connect()
        result = store.reconstruct_result(con, source)
        con.close()
        if result is None:
            raise click.ClickException(f"scan id '{source}' not found in the store")
    else:
        with open(source, encoding="utf-8") as fh:
            result = _json.load(fh)
    rmeta = {k: v for k, v in dict(client=client, scope=scope, window=window,
             prepared_by=prepared_by, ref=ref, logo=logo, when=when).items() if v is not None}
    n = len(result.get("findings", []))
    base = os.path.splitext(out)[0]
    if fmt.strip().lower() == "auto":
        fmts = ["pdf"] if out.lower().endswith(".pdf") else \
               ["csv"] if out.lower().endswith(".csv") else \
               ["xlsx"] if out.lower().endswith((".xlsx", ".xls")) else ["html"]
    elif fmt.strip().lower() == "all":
        fmts = ["html", "xlsx", "csv", "pdf"]
    else:
        fmts = [x.strip().lower() for x in fmt.split(",") if x.strip()]
    _html = None
    written = []
    for fm in fmts:
        if fm in ("html", "pdf") and _html is None:
            _html = build_report(result, target=target, meta=rmeta, concise=concise)
        if fm == "html":
            p = base + ".html"
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(_html)
        elif fm == "pdf":
            from .report import render_pdf
            p = base + ".pdf"
            render_pdf(_html, p)
        elif fm == "xlsx":
            from .export import to_xlsx
            p = base + ".xlsx"
            to_xlsx(result, p, meta={**rmeta, "target": target})
        elif fm == "csv":
            from .export import to_csv
            p = base + ".csv"
            to_csv(result, p)
        else:
            continue
        written.append(p)
    console.print(f"[green]report[/green] -> {', '.join(written)}  ({n} findings"
                  f"{', concise' if concise else ''})")
    if open_it and written:
        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(written[0])}")


@main.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8810, type=int)
@click.option("--db", "db_path_opt", default=None,
              help="SQLite store to serve (default ~/.d4st/d4st.db). Populate it with "
                   "`d4st ingest`; scans also auto-ingest at scan-end.")
def serve(host: str, port: int, db_path_opt: str | None) -> None:
    """Start the d4st web console (observability dashboard + report viewer)."""
    from .server import run_server
    run_server(host=host, port=port, db_path=db_path_opt)


if __name__ == "__main__":
    main()
