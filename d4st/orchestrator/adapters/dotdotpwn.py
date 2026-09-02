"""dotdotpwn adapter (detection, active) — targeted deep traversal on a single endpoint.

dotdotpwn's TraversalEngine generates traversal permutations (depth x encoding x separator).
It is thorough but slow (hundreds of requests/URL), so it is NOT the mass-scan engine
(lfi_fuzz/ffuf covers breadth fast); it is a targeted deep pass for a specific suspicious
endpoint, bounded by depth so it terminates. Confirms via keyword match on the response.

Vendored (Perl) at vendor/dotdotpwn; run with -I so its lib is on @INC.
"""

from __future__ import annotations

import os
import re
from urllib.parse import parse_qs, urlsplit

from .base import AdapterResult, RunContext, ToolAdapter, register

_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "vendor", "dotdotpwn")
_SCRIPT = os.path.join(_DIR, "dotdotpwn.pl")
_FOUND = re.compile(r"<-\s*VULNERABLE|\[\+\].*(root:x:0:0|\[extensions\])", re.IGNORECASE)


def _first_param(url: str) -> str | None:
    q = parse_qs(urlsplit(url).query)
    return next(iter(q), None)


@register
class DotDotPwnAdapter(ToolAdapter):
    name = "dotdotpwn"
    stage = "scan"
    discovers = False
    detects = True
    active = True
    binary = "perl"

    def available(self) -> bool:
        return super().available() and os.path.exists(_SCRIPT)

    def run(self, ctx: RunContext) -> AdapterResult:
        # single-endpoint tool: only runs when explicitly given a target URL with a param
        url = ctx.options.get("dotdotpwn_url") or (ctx.seed_urls[0] if ctx.seed_urls else ctx.target)
        param = _first_param(url)
        if not param:
            return AdapterResult(tool=self.name, ok=True, note="no parameterized URL")
        base = url.split("?")[0]
        depth = str(ctx.options.get("dotdotpwn_depth", 5))
        pattern = ctx.options.get("dotdotpwn_pattern", "root:x:0:0")
        target = f"{base}?{param}=TRAVERSAL"
        args = ["perl", "-I", _DIR, _SCRIPT, "-m", "http-url", "-u", target,
                "-k", pattern, "-d", depth, "-t", "0", "-q", "-b"]
        cmd = " ".join(args)
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd,
                                 note="perl or vendored dotdotpwn.pl missing")
        try:
            proc = self._exec(args, timeout=ctx.options.get("timeout", 300))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")
        hit = bool(_FOUND.search(proc.stdout or ""))
        findings = [{"type": "lfi", "url": base, "param": param, "matched-at": base,
                     "evidence": "dotdotpwn traversal confirmed"}] if hit else []
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{'VULNERABLE' if hit else 'no traversal found'}", raw=proc.stdout)
