"""commix OS-command-injection adapter (detection, active).

commix takes one --url at a time; we iterate the frontier's parameterized URLs (capped) in
--batch mode and parse confirmed command-injection points from stdout.
"""

from __future__ import annotations

import re
import tempfile

from ._targets import candidate_urls
from .base import AdapterResult, RunContext, ToolAdapter, map_bounded, register
from .session_util import _cookie_header

# commix reports e.g. (wording varies by version/technique):
#   POST parameter 'ip' appears to be injectable via (results-based) classic command injection
#   POST parameter 'ip' is likely vulnerable ...
#   The (GET) 'ip' parameter is vulnerable to ... (older phrasing)
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_VULN_RE = re.compile(
    r"\(?(?P<place>GET|POST)\)?\s+parameter\s+'(?P<param>[^']+)'\s+"
    r"(?:appears to be injectable|is (?:likely )?vulnerable)",
    re.IGNORECASE,
)
# older phrasing: "(GET) 'ip' parameter is vulnerable"
_VULN_RE_OLD = re.compile(
    r"\((?P<place>GET|POST)\)\s*'(?P<param>[^']+)'\s*parameter is vulnerable",
    re.IGNORECASE,
)


def parse_commix(text: str, url: str = "") -> list[dict]:
    text = _ANSI.sub("", text or "")
    seen: set = set()
    out: list[dict] = []
    for rx in (_VULN_RE, _VULN_RE_OLD):
        for m in rx.finditer(text):
            key = (m.group("param"), m.group("place").upper())
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "tool": "commix",
                "url": url,
                "param": m.group("param"),
                "place": m.group("place").upper(),
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
        _d = ctx.options.get("delay_ms")
        _timeout = min(int(ctx.options.get("timeout", 900)), 150)

        def _probe(url: str) -> list[dict]:
            out_dir = tempfile.mkdtemp(prefix="commix_")
            args = ["commix", "--url", url, "--batch", "--output-dir", out_dir]
            if _d:   # honor scan politeness between requests
                args += ["--delay", str(max(1, int(_d / 1000)))]
            if cookie:
                args += ["--cookie", cookie]
            # per-URL wall-time cap: don't let one target burn the roster's full budget
            proc = self._exec(args, timeout=_timeout)
            return parse_commix(proc.stdout, url)

        # Bounded fan-out over the target list. Pool size = the scan's concurrency ceiling
        # (workers), so this honors the same politeness as every other stage: serial on gentle
        # profiles (safe-deep concurrency=2 stays ~2-way), parallel on faster ones — instead of
        # the old strictly-serial grind that ignored the concurrency knob and cost hours.
        _errors = [0]
        results = map_bounded(_probe, targets, ctx.options.get("workers", 1),
                              on_error=lambda _e: _errors.__setitem__(0, _errors[0] + 1))
        findings: list[dict] = []
        for r in results:
            findings.extend(r or [])
        errors = _errors[0]

        note = f"{len(findings)} cmd-injection point(s)"
        if errors:
            note += f" ({errors} target error(s))"
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd, note=note)
