"""OWASP ZAP adapter (discovery + detection, active).

Runs the packaged `zap-full-scan.py` (spider + AJAX spider + active scan) and parses its
JSON report: alerts become findings, alert instance URIs feed the frontier. Full session/auth
injection via a ZAP context lands in Phase 3 (the crawl-controlled pilot); for now the session
cookie is passed best-effort via a ZAP replacer option.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile

from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header, _session_headers

# ZAP riskcode -> severity
_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}


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


def _replacer_config(idx: int, match: str, replacement: str) -> str:
    """One ZAP `replacer` rule: set REQ_HEADER `match` to `replacement` on every request."""
    return (
        f"-config replacer.full_list({idx}).description=auth{idx} "
        f"-config replacer.full_list({idx}).enabled=true "
        f"-config replacer.full_list({idx}).matchtype=REQ_HEADER "
        f"-config replacer.full_list({idx}).matchstr={match} "
        f"-config replacer.full_list({idx}).replacement={replacement}"
    )


def _auth_config(cookie: str, headers: dict | None) -> str:
    """Best-effort auth for ZAP: inject the Cookie AND any non-cookie session headers
    (e.g. `Authorization: Bearer <jwt>` for token/SPA sessions — the Cookie-only path left
    JWT-authenticated apps scanned logged-out). One replacer rule per header."""
    rules: list[str] = []
    idx = 0
    if cookie:
        rules.append(_replacer_config(idx, "Cookie", cookie)); idx += 1
    for k, v in (headers or {}).items():
        if not k or k.lower() == "cookie" or v is None:
            continue
        rules.append(_replacer_config(idx, k, v)); idx += 1
    return " ".join(rules)


def build_zap_args(target: str, cookie: str, options: dict, headers: dict | None = None) -> list[str]:
    """Assemble the zap-full-scan.py argv. `-j` enables the AJAX Spider; we always tune it deeper.
    Extracted so the invocation is unit-testable without a ZAP install."""
    args = ["zap-full-scan.py", "-t", target, "-J", "report.json", "-j"]
    zcfg = _ajax_config(options)
    auth = _auth_config(cookie, headers)
    if auth:
        zcfg = auth + " " + zcfg
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
        cmd = f"zap-full-scan.py -t {ctx.target} -J report.json -j (AJAX spider tuned deep)"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run (not executed)")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd,
                                 note="zap-full-scan.py not found on PATH")

        try:
            workdir = tempfile.mkdtemp(prefix="zap_")
            report_path = os.path.join(workdir, "report.json")
            cookie = _cookie_header(ctx.session, ctx.target)
            headers = _session_headers(ctx.session)
            args = build_zap_args(ctx.target, cookie, ctx.options, headers=headers)
            proc = self._exec(args, timeout=ctx.options.get("timeout", 3600))
            report = None
            # zap-full-scan writes the report into its working directory
            for cand in (report_path, os.path.join(os.getcwd(), "report.json")):
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

        # Distinguish a real failure (no report / zap error rc>=3) from a clean 0-alert run.
        # Previously any rc not in (0,1,2) was reported as a bland "0 alert(s), 0 url(s)" which
        # hid the actual reason (ZAP couldn't start, AJAX browser missing, target unreachable…).
        if report is None:
            tail = ((proc.stderr or proc.stdout or "").strip().splitlines() or [""])[-1][:200]
            return AdapterResult(
                tool=self.name, ok=False, command=cmd, raw=None,
                note=f"no report produced (zap rc={proc.returncode}): {tail or 'see zap output'}",
            )

        findings, urls = parse_zap(report)
        # zap-full-scan exits 0/1/2 for pass/fail/warn (all successful runs). rc>=3 is a run
        # error, but if a report WAS written we still parse it and flag the anomaly in the note.
        run_ok = proc.returncode in (0, 1, 2)
        note = f"{len(findings)} alert(s), {len(urls)} url(s)"
        if not run_ok:
            note += f" (warning: zap rc={proc.returncode})"
        return AdapterResult(
            tool=self.name, ok=True,  # a report was produced → the stage succeeded
            findings=findings, discovered_urls=urls, command=cmd,
            note=note, raw=report,
        )
