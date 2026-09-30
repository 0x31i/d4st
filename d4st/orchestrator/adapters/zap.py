"""OWASP ZAP adapter (discovery + detection, active).

Runs the packaged `zap-full-scan.py` (spider + AJAX spider + active scan) and parses its
JSON report: alerts become findings, alert instance URIs feed the frontier. Full session/auth
injection via a ZAP context lands in Phase 3 (the crawl-controlled pilot); for now the session
cookie is passed best-effort via a ZAP replacer option.
"""

from __future__ import annotations

import json
import os
import tempfile

from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header

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


def _cookie_config(cookie: str) -> str:
    """Best-effort auth: replace the Cookie header on every ZAP request."""
    return (
        "-config replacer.full_list(0).description=auth "
        "-config replacer.full_list(0).enabled=true "
        "-config replacer.full_list(0).matchtype=REQ_HEADER "
        "-config replacer.full_list(0).matchstr=Cookie "
        f"-config replacer.full_list(0).replacement={cookie}"
    )


def build_zap_args(target: str, cookie: str, options: dict) -> list[str]:
    """Assemble the zap-full-scan.py argv. `-j` enables the AJAX Spider; we always tune it deeper.
    Extracted so the invocation is unit-testable without a ZAP install."""
    args = ["zap-full-scan.py", "-t", target, "-J", "report.json", "-j"]
    zcfg = _ajax_config(options)
    if cookie:
        zcfg = _cookie_config(cookie) + " " + zcfg
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
            args = build_zap_args(ctx.target, cookie, ctx.options)
            proc = self._exec(args, timeout=ctx.options.get("timeout", 3600))
            report = {}
            # zap-full-scan writes the report into its working directory
            for cand in (report_path, os.path.join(os.getcwd(), "report.json")):
                if os.path.exists(cand):
                    with open(cand, "r", encoding="utf-8") as fh:
                        report = json.load(fh)
                    break
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")

        findings, urls = parse_zap(report)
        # zap-full-scan exits non-zero when it finds alerts; treat that as success.
        return AdapterResult(
            tool=self.name, ok=proc.returncode in (0, 1, 2),
            findings=findings, discovered_urls=urls, command=cmd,
            note=f"{len(findings)} alert(s), {len(urls)} url(s)",
            raw=report,
        )
