"""commix OS-command-injection adapter (detection, active).

commix takes one --url at a time; we iterate the frontier's parameterized URLs (capped) in
--batch mode and parse confirmed command-injection points from stdout.
"""

from __future__ import annotations

import re
import tempfile

from ._targets import candidate_urls
from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header

# commix reports e.g.:
#   The (GET) 'ip' parameter is vulnerable to results-based command injection technique.
_VULN_RE = re.compile(
    r"\((?P<place>GET|POST)\)\s*'(?P<param>[^']+)'\s*parameter is vulnerable",
    re.IGNORECASE,
)


def parse_commix(text: str, url: str = "") -> list[dict]:
    out: list[dict] = []
    for m in _VULN_RE.finditer(text or ""):
        out.append({
            "tool": "commix",
            "url": url,
            "param": m.group("param"),
            "place": m.group("place"),
            "category": "command-injection",
        })
    return out


@register
class CommixAdapter(ToolAdapter):
    name = "commix"
    stage = "scan"
    discovers = False
    detects = True
    active = True
    binary = "commix"

    def run(self, ctx: RunContext) -> AdapterResult:
        targets = candidate_urls(ctx.seed_urls or [ctx.target], require_params=True,
                                 cap=ctx.options.get("inject_cap", 0))
        if not targets:
            return AdapterResult(tool=self.name, ok=True,
                                 note="no parameterized URLs to test")
        cmd = f"commix --url <each of {len(targets)}> --batch"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd,
                                 note=f"dry-run over {len(targets)} url(s)")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd,
                                 note="commix binary not found on PATH")

        cookie = _cookie_header(ctx.session, ctx.target)
        findings: list[dict] = []
        errors = 0
        for url in targets:
            try:
                out_dir = tempfile.mkdtemp(prefix="commix_")
                args = ["commix", "--url", url, "--batch", "--output-dir", out_dir]
                if cookie:
                    args += ["--cookie", cookie]
                proc = self._exec(args, timeout=ctx.options.get("timeout", 900))
                findings.extend(parse_commix(proc.stdout, url))
            except Exception:  # noqa: BLE001 - one target failing must not sink the rest
                errors += 1

        note = f"{len(findings)} cmd-injection point(s)"
        if errors:
            note += f" ({errors} target error(s))"
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd, note=note)
