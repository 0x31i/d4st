"""ghauri SQLi adapter (detection, active).

Complements sqlmap: ghauri is a faster blind/time-based SQLi engine that catches some cases
sqlmap's blind heuristics miss. Runs per candidate URL, parses the CLI verdict. Union with
sqlmap raises SQLi recall without changing precision (both confirm before reporting).
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from ._targets import candidate_urls
from .base import AdapterResult, RunContext, ToolAdapter, map_bounded, register
from .session_util import _cookie_header

_VULN = re.compile(r"is vulnerable|parameter '[^']+' is vulnerable|appears to be injectable|"
                   r"injectable", re.IGNORECASE)


def _first_param(url: str) -> str | None:
    q = parse_qs(urlsplit(url).query)
    return next(iter(q), None)


@register
class GhauriAdapter(ToolAdapter):
    name = "ghauri"
    stage = "scan"
    discovers = False
    detects = True
    active = True
    binary = "ghauri"

    def run(self, ctx: RunContext) -> AdapterResult:
        targets = candidate_urls(ctx.seed_urls or [ctx.target], require_params=True,
                                 cap=ctx.options.get("inject_cap", 0))
        if not targets:
            return AdapterResult(tool=self.name, ok=True, note="no parameterized URLs")
        cmd = f"ghauri over {len(targets)} url(s) --level {ctx.options.get('sqli_level', 3)}"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd,
                                 note="ghauri binary not found on PATH")

        cookie = _cookie_header(ctx.session, ctx.target)
        level = str(ctx.options.get("sqli_level", 3))
        _d = ctx.options.get("delay_ms")
        _timeout = ctx.options.get("per_url_timeout", 120)
        _http_to = str(ctx.options.get("http_timeout", 10))

        def _probe(url: str) -> dict | None:
            args = ["ghauri", "-u", url, "--batch", "--level", level, "--timeout", _http_to]
            if _d:   # honor scan politeness: seconds between requests
                args += ["--delay", str(max(1, int(_d / 1000)))]
            if cookie:
                args += ["--cookie", cookie]
            proc = self._exec(args, timeout=_timeout)
            if _VULN.search(proc.stdout or ""):
                return {"type": "sqli", "url": url.split("?")[0],
                        "param": _first_param(url), "matched-at": url.split("?")[0],
                        "evidence": "ghauri confirmed injectable"}
            return None

        # Bounded fan-out over the target list (see commix adapter): pool size = the scan's
        # concurrency ceiling (workers), so it stays as polite as every other stage.
        findings = [f for f in map_bounded(_probe, targets, ctx.options.get("workers", 1)) if f]
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{len(findings)} confirmed SQLi")
