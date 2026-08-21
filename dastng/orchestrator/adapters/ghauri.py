"""ghauri SQLi adapter (detection, active).

Complements sqlmap: ghauri is a faster blind/time-based SQLi engine that catches some cases
sqlmap's blind heuristics miss. Runs per candidate URL, parses the CLI verdict. Union with
sqlmap raises SQLi recall without changing precision (both confirm before reporting).
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from ._targets import candidate_urls
from .base import AdapterResult, RunContext, ToolAdapter, register
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
        findings: list[dict] = []
        for url in targets:
            args = ["ghauri", "-u", url, "--batch", "--level", level,
                    "--timeout", str(ctx.options.get("http_timeout", 10))]
            if cookie:
                args += ["--cookie", cookie]
            try:
                proc = self._exec(args, timeout=ctx.options.get("per_url_timeout", 120))
            except Exception:  # noqa: BLE001,S112 - one URL's tool error must not sink the scan
                continue
            if _VULN.search(proc.stdout or ""):
                findings.append({"type": "sqli", "url": url.split("?")[0],
                                 "param": _first_param(url), "matched-at": url.split("?")[0],
                                 "evidence": "ghauri confirmed injectable"})
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{len(findings)} confirmed SQLi")
