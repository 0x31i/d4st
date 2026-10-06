"""OWASP ZAP adapter (discovery + detection, active).

Runs the packaged `zap-full-scan.py` (spider + AJAX spider + active scan) and parses its
JSON report: alerts become findings, alert instance URIs feed the frontier.

Isolation + correctness (learned from a a concurrent sweep):
- Each run gets its OWN writable workdir + HOME + a UNIQUE report filename + a free listen port,
  so two ZAP runs in parallel can never share session state / report files (cross-contamination).
- Auth is injected as ZAP `replacer` rules. Values with spaces (e.g. `Authorization: Bearer <jwt>`)
  CANNOT go in the `-z` string — zap-full-scan.py splits it on spaces, so a space mid-value breaks
  arg parsing (the rc=3 / python-traceback failure on bearer sessions). Those rules are written to a
  properties file and loaded via `-configfile` (no space-splitting); space-free rules stay inline.
- Findings are scope-filtered and adjudicated (ZAP's version-only "Vulnerable JS Library" and
  pattern-only "PII Disclosure" are FP-prone) before they leave the adapter.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import tempfile

from ...scope import in_scope, scope_hosts
from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header, _session_headers

# ZAP riskcode -> severity
_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}

# ZAP passive-scan plugin ids we adjudicate (FP-prone).
_PLUGIN_VULN_JS = "10003"   # "Vulnerable JS Library" — version-only; flags current releases
_PLUGIN_PII = "10062"       # "PII Disclosure" — regex/Luhn match; fires on IDs & build numbers

# URIs where a "PII" number is almost certainly a build/cache/service-worker artifact, not PII.
_FP_ARTIFACT_RE = re.compile(
    r"(?i)(ngsw\.json|ngsw-worker|\.map(?:\?|$)|/assets/|[?&][a-z0-9_]*=0\.\d|"
    r"\bchunk[.\-]|\bruntime[.\-]|\bpolyfills[.\-]|\bmain[.\-]|\bvendor[.\-])")


def parse_zap(report: dict) -> tuple[list[dict], list[str]]:
    """Return (findings, discovered_urls) from a ZAP traditional-JSON report."""
    findings: list[dict] = []
    urls: set[str] = set()
    for site in report.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            instances = alert.get("instances", []) or []
            for inst in instances:
                if inst.get("uri"):
                    urls.add(inst["uri"])
            findings.append({
                "tool": "zap",
                "name": alert.get("alert") or alert.get("name"),
                "pluginid": alert.get("pluginid"),
                "severity": _RISK.get(str(alert.get("riskcode")), "info"),
                "confidence": alert.get("confidence"),
                "cweid": alert.get("cweid"),
                "wascid": alert.get("wascid"),
                "desc": alert.get("desc"),
                "solution": alert.get("solution"),
                "instances": [
                    {"uri": i.get("uri"), "method": i.get("method"),
                     "param": i.get("param"), "evidence": i.get("evidence")}
                    for i in instances
                ],
                "count": alert.get("count"),
            })
    return findings, sorted(urls)


def adjudicate_zap(findings: list[dict]) -> list[dict]:
    """Down-rate ZAP's two FP-prone 'High' rules so they don't ship as confirmed Highs.

    - Vulnerable JS Library (10003): version-only — ZAP calls CURRENT framework releases
      vulnerable (seen flagging Angular 20.3.9 / 18.0.5). Cap at 'low' + flag for CVE-range check.
    - PII Disclosure (10062): a pattern/Luhn match — fires on service-worker cache numbers
      (e.g. ngsw.json build ids) as 'credit card'. If every instance URI is a build/cache artifact,
      drop to 'info'; otherwise keep but flag as a pattern match to verify.
    Severity only moves DOWN; the raw alert is preserved. Non-destructive (edits a copy's fields)."""
    for f in findings:
        pid = str(f.get("pluginid") or "")
        note = f.get("verify_note") or ""
        if pid == _PLUGIN_VULN_JS and f.get("severity") == "high":
            f["severity"] = "low"
            f["verify_note"] = (note + " [d4st: ZAP version-only detection, downgraded from High — "
                                "confirm the detected version is within a PUBLISHED CVE range "
                                "(ZAP flags current releases as vulnerable).]").strip()
        elif pid == _PLUGIN_PII:
            uris = " ".join((i.get("uri") or "") for i in (f.get("instances") or []))
            if uris and _FP_ARTIFACT_RE.search(uris) and not _has_non_artifact_uri(f):
                if f.get("severity") in ("high", "medium", "low"):
                    f["severity"] = "info"
                f["verify_note"] = (note + " [d4st: ZAP 'PII' match in a build/service-worker "
                                    "artifact (e.g. ngsw.json cache number) — not real PII; "
                                    "downgraded to info.]").strip()
            else:
                f["verify_note"] = (note + " [d4st: ZAP 'PII' is a pattern/Luhn match — verify this "
                                    "is actual PII (CC/SSN) and not an ID/sequence before reporting.]").strip()
    return findings


def _has_non_artifact_uri(f: dict) -> bool:
    for i in (f.get("instances") or []):
        u = i.get("uri") or ""
        if u and not _FP_ARTIFACT_RE.search(u):
            return True
    return False


def scope_filter(findings: list[dict], urls: list[str], hosts) -> tuple[list[dict], list[str]]:
    """Drop off-scope ZAP results (its spider follows the app's third-party XHRs — e.g.
    checkip.amazonaws.com / v4.ident.me — and reports findings on them). Uses the ONE canonical
    scope definition. A finding is kept only if it has an in-scope instance (or no instances at
    all = site-level); its off-scope instances are stripped."""
    if not hosts:
        return findings, urls
    kept: list[dict] = []
    for f in findings:
        insts = f.get("instances") or []
        if not insts:
            kept.append(f)
            continue
        in_insts = [i for i in insts if in_scope(i.get("uri") or "", hosts)]
        if in_insts:
            f = dict(f)
            f["instances"] = in_insts
            f["count"] = len(in_insts)
            kept.append(f)
    urls = [u for u in urls if in_scope(u, hosts)]
    return kept, urls


def _ajax_config(options: dict) -> str:
    """ZAP `-config` string tuning the AJAX Spider for depth on JS-heavy / ASP.NET WebForms apps.
    The AJAX spider drives a real browser and triggers __doPostBack/JS navigation the traditional
    spider misses; its CLI defaults are shallow, so we push crawl depth + duration and click every
    element. All values are generic knobs (no target specifics), overridable via options/env."""
    o = options or {}
    depth = int(o.get("zap_ajax_depth", os.environ.get("D4ST_ZAP_AJAX_DEPTH", 10)))
    dur = int(o.get("zap_ajax_duration_min", os.environ.get("D4ST_ZAP_AJAX_DURATION", 10)))
    browsers = int(o.get("zap_ajax_browsers", os.environ.get("D4ST_ZAP_AJAX_BROWSERS", 1)))
    browser = o.get("zap_ajax_browser", os.environ.get("D4ST_ZAP_AJAX_BROWSER", "firefox-headless"))
    return (
        f"-config ajaxSpider.maxCrawlDepth={depth} "
        f"-config ajaxSpider.maxDuration={dur} "
        f"-config ajaxSpider.numberOfBrowsers={browsers} "
        f"-config ajaxSpider.browserId={browser} "
        # click every element (not once) so grid paging / dropdown postbacks are all exercised
        "-config ajaxSpider.clickElemsOnce=false "
        "-config ajaxSpider.clickDefaultElems=false"
    )


def _auth_rules(cookie: str, headers: dict | None) -> list[tuple[int, str, str]]:
    """(idx, header-name, value) replacer rules: Cookie first, then non-cookie session headers
    (e.g. Authorization: Bearer <jwt>). Dedups a Cookie already carried in `headers`."""
    rules: list[tuple[int, str, str]] = []
    idx = 0
    if cookie:
        rules.append((idx, "Cookie", cookie)); idx += 1
    for k, v in (headers or {}).items():
        if not k or k.lower() == "cookie" or v is None:
            continue
        rules.append((idx, k, v)); idx += 1
    return rules


def _rules_need_configfile(rules: list[tuple[int, str, str]]) -> bool:
    """True if any rule value/name has a char unsafe in the space-split `-z` string (a space is the
    killer: `Bearer <jwt>` -> zap-full-scan splits mid-value -> rc=3). Such rules go in a configfile."""
    for _, m, v in rules:
        if any(c.isspace() for c in str(m)) or any(c.isspace() for c in str(v)):
            return True
    return False


def _replacer_inline(rules: list[tuple[int, str, str]]) -> str:
    """Render replacer rules as inline `-z` `-config` directives (space-free values only)."""
    out: list[str] = []
    for idx, match, replacement in rules:
        out.append(
            f"-config replacer.full_list({idx}).description=auth{idx} "
            f"-config replacer.full_list({idx}).enabled=true "
            f"-config replacer.full_list({idx}).matchtype=REQ_HEADER "
            f"-config replacer.full_list({idx}).matchstr={match} "
            f"-config replacer.full_list({idx}).replacement={replacement}"
        )
    return " ".join(out)


def _replacer_properties(rules: list[tuple[int, str, str]]) -> str:
    """Render replacer rules as a Java-properties file (loaded via `-configfile`). Properties split
    on the first `=`, so values may contain spaces (the bearer case) without breaking anything."""
    lines: list[str] = []
    for idx, match, replacement in rules:
        lines += [
            f"replacer.full_list({idx}).description=auth{idx}",
            f"replacer.full_list({idx}).enabled=true",
            f"replacer.full_list({idx}).matchtype=REQ_HEADER",
            f"replacer.full_list({idx}).matchstr={match}",
            f"replacer.full_list({idx}).replacement={replacement}",
        ]
    return "\n".join(lines) + "\n"


def _free_port() -> int:
    """An OS-assigned free TCP port, so concurrent ZAP daemons never collide on one listener."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def build_zap_args(target: str, cookie: str, options: dict, headers: dict | None = None,
                   auth_conf_path: str | None = None, port: int | None = None,
                   report_name: str = "report.json") -> list[str]:
    """Assemble the zap-full-scan.py argv. `-j` enables the AJAX Spider; we always tune it deeper.
    When auth rules need a configfile (spaces in values) AND `auth_conf_path` is given, auth is
    referenced via `-configfile` (space-free token); otherwise it's inlined in `-z`. `-P <port>`
    isolates the listener for concurrency. Pure/arg-only so it's unit-testable without a ZAP install."""
    rules = _auth_rules(cookie, headers)
    frags: list[str] = []
    if rules:
        if auth_conf_path and _rules_need_configfile(rules):
            frags.append(f"-configfile {auth_conf_path}")
        else:
            frags.append(_replacer_inline(rules))
    frags.append(_ajax_config(options))
    zcfg = " ".join(p for p in frags if p)

    args = ["zap-full-scan.py", "-t", target, "-J", report_name, "-j"]
    if port and os.environ.get("D4ST_ZAP_NO_PORT") != "1":
        args += ["-P", str(port)]
    args += ["-z", zcfg]
    return args


@register
class ZapAdapter(ToolAdapter):
    name = "zap"
    stage = "scan"
    discovers = True
    detects = True
    active = True
    binary = "zap-full-scan.py"

    def run(self, ctx: RunContext) -> AdapterResult:
        cmd = f"zap-full-scan.py -t {ctx.target} -J <unique>.json -j (AJAX spider tuned deep)"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run (not executed)")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd,
                                 note="zap-full-scan.py not found on PATH")

        try:
            workdir = tempfile.mkdtemp(prefix="zap_")
            # UNIQUE report name per run so concurrent runs can't read each other's report even if
            # ZAP drops it in a shared mount (/zap/wrk) — the cross-contamination seen in the sweep.
            token = os.path.basename(workdir).replace("zap_", "") or "run"
            report_name = f"report-{token}.json"
            report_path = os.path.join(workdir, report_name)

            cookie = _cookie_header(ctx.session, ctx.target)
            headers = _session_headers(ctx.session)
            # Spaces in a replacer value (Authorization: Bearer <jwt>) break `-z`; write those rules
            # to a properties file loaded via `-configfile` instead.
            auth_conf_path = None
            rules = _auth_rules(cookie, headers)
            if rules and _rules_need_configfile(rules):
                auth_conf_path = os.path.join(workdir, "zap_auth.properties")
                with open(auth_conf_path, "w", encoding="utf-8") as fh:
                    fh.write(_replacer_properties(rules))

            port = _free_port()
            args = build_zap_args(ctx.target, cookie, ctx.options, headers=headers,
                                  auth_conf_path=auth_conf_path, port=port, report_name=report_name)
            # Run ZAP INSIDE the writable workdir and point HOME there (rc=3 "file based operation"
            # cause when cwd/HOME aren't writable). Fresh mkdtemp under /tmp is always writable and
            # per-run (session isolation).
            env = dict(os.environ)
            env["HOME"] = workdir
            proc = self._exec(args, timeout=ctx.options.get("timeout", 3600),
                              cwd=workdir, env=env)
            report = None
            # Look only for THIS run's unique report name (never a bare shared "report.json"), in the
            # workdir first, then ZAP's legacy /zap/wrk mount and the launcher cwd.
            for cand in (report_path,
                         os.path.join("/zap/wrk", report_name),
                         os.path.join(os.getcwd(), report_name)):
                if os.path.exists(cand):
                    with open(cand, "r", encoding="utf-8") as fh:
                        report = json.load(fh)
                    break
        except subprocess.TimeoutExpired:
            to = ctx.options.get("timeout", 3600)
            return AdapterResult(tool=self.name, ok=False, command=cmd,
                                 note=f"TIMEOUT after {to}s (killed) — raise options.timeout or "
                                      f"narrow scope; partial report discarded")
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")

        if report is None:
            lines = [ln.strip() for ln in (proc.stderr or proc.stdout or "").splitlines() if ln.strip()]
            tail = " | ".join(lines[-4:])[:400]
            return AdapterResult(
                tool=self.name, ok=False, command=cmd, raw=None,
                note=f"no report produced (zap rc={proc.returncode}): {tail or 'see zap output'}",
            )

        findings, urls = parse_zap(report)
        findings = adjudicate_zap(findings)                       # down-rate FP-prone Highs
        hosts = scope_hosts(ctx.target)
        findings, urls = scope_filter(findings, urls, hosts)      # drop off-scope (third-party) alerts
        run_ok = proc.returncode in (0, 1, 2)
        note = f"{len(findings)} alert(s), {len(urls)} url(s)"
        if not run_ok:
            note += f" (warning: zap rc={proc.returncode})"
        return AdapterResult(
            tool=self.name, ok=True,  # a report was produced → the stage succeeded
            findings=findings, discovered_urls=urls, command=cmd,
            note=note, raw=report,
        )
