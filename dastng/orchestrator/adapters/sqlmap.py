"""sqlmap SQL-injection adapter (detection, active).

sqlmap has no clean machine output, so we run it in --batch over the frontier's parameterized
URLs (multi-target -m list) and parse the confirmed injection points from stdout. Deep dumping
is intentionally disabled: this is detection, not exfiltration.
"""

from __future__ import annotations

import re
import tempfile

from ._targets import candidate_urls
from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header

# "sqlmap identified the following injection point(s)" then blocks of:
#   Parameter: id (GET)
#       Type: boolean-based blind
#       Title: ...
_PARAM_RE = re.compile(r"^Parameter:\s*(?P<param>.+?)\s*\((?P<place>\w+)\)", re.MULTILINE)
_TYPE_RE = re.compile(r"^\s*Type:\s*(?P<type>.+)$", re.MULTILINE)
_URL_RE = re.compile(r"^\[.*\]\s*\[INFO\]\s*testing URL '(?P<url>\S+)'", re.MULTILINE)


def parse_sqlmap(text: str) -> list[dict]:
    """Extract confirmed injection points from sqlmap stdout."""
    text = text or ""
    if "injection point" not in text and "is vulnerable" not in text and "Parameter:" not in text:
        return []
    findings: list[dict] = []
    for m in _PARAM_RE.finditer(text):
        # collect the Type lines that follow this Parameter block (until the next Parameter)
        start = m.end()
        nxt = _PARAM_RE.search(text, start)
        block = text[start:nxt.start()] if nxt else text[start:]
        types = [t.group("type").strip() for t in _TYPE_RE.finditer(block)]
        findings.append({
            "tool": "sqlmap",
            "param": m.group("param"),
            "place": m.group("place"),
            "types": types,
            "category": "sql-injection",
        })
    return findings


@register
class SqlmapAdapter(ToolAdapter):
    name = "sqlmap"
    stage = "scan"
    discovers = False
    detects = True
    active = True
    binary = "sqlmap"

    def run(self, ctx: RunContext) -> AdapterResult:
        targets = candidate_urls(ctx.seed_urls or [ctx.target], require_params=True,
                                 cap=ctx.options.get("inject_cap", 0))
        if not targets:
            return AdapterResult(tool=self.name, ok=True,
                                 note="no parameterized URLs to test")
        level = ctx.options.get("sqlmap_level", 1)
        risk = ctx.options.get("sqlmap_risk", 1)
        cmd = f"sqlmap -m <{len(targets)} urls> --batch --level {level} --risk {risk}"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd,
                                 note=f"dry-run over {len(targets)} url(s)")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd,
                                 note="sqlmap binary not found on PATH")

        try:
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
                fh.write("\n".join(targets))
                list_path = fh.name
            out_dir = tempfile.mkdtemp(prefix="sqlmap_")
            args = ["sqlmap", "-m", list_path, "--batch", "--disable-coloring",
                    "--level", str(level), "--risk", str(risk), "--output-dir", out_dir]
            cookie = _cookie_header(ctx.session, ctx.target)
            if cookie:
                args += ["--cookie", cookie]
            proc = self._exec(args, timeout=ctx.options.get("timeout", 3600))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")

        findings = parse_sqlmap(proc.stdout)
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{len(findings)} injection point(s)", raw=proc.stdout)
