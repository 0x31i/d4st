"""API-focused adapters: jwt_tool (JWT attacks), graphw00f (GraphQL fingerprint),
schemathesis (OpenAPI/GraphQL stateful fuzzing). These fire only when the relevant surface
exists (a JWT, a GraphQL endpoint, an OpenAPI schema), so on a classic app they cleanly
report "not applicable" rather than failing.
"""

from __future__ import annotations

import re

from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def parse_jwt_tool(text: str) -> list[dict]:
    text = _ANSI.sub("", text or "")
    out: list[dict] = []
    # jwt_tool flags issues like: "[+] alg:none ... VULNERABLE"
    for m in re.finditer(r"(?P<issue>alg[:=]?none|key confusion|weak.*secret|kid injection)",
                         text, re.IGNORECASE):
        out.append({"tool": "jwt_tool", "issue": m.group("issue"), "category": "other"})
    return out


def parse_graphw00f(text: str) -> list[dict]:
    text = _ANSI.sub("", text or "")
    m = re.search(r"Discovered GraphQL Engine:\s*\(?(?P<engine>[^)\n]+)\)?", text, re.IGNORECASE)
    if m:
        return [{"tool": "graphw00f", "engine": m.group("engine").strip(), "category": "other"}]
    return []


@register
class JwtToolAdapter(ToolAdapter):
    name = "jwt_tool"
    stage = "scan"
    discovers = False
    detects = True
    active = True
    binary = "jwt_tool"

    def run(self, ctx: RunContext) -> AdapterResult:
        token = ctx.options.get("jwt")
        cmd = "jwt_tool <token> -M at"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="jwt_tool not found")
        if not token:
            return AdapterResult(tool=self.name, ok=True, command=cmd,
                                 note="no JWT provided (not applicable)")
        try:
            proc = self._exec(["jwt_tool", token, "-M", "at"],
                              timeout=ctx.options.get("timeout", 300))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")
        findings = parse_jwt_tool(proc.stdout)
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{len(findings)} jwt issue(s)")


@register
class Graphw00fAdapter(ToolAdapter):
    name = "graphw00f"
    stage = "recon"
    discovers = False
    detects = True
    active = False
    binary = "graphw00f"

    def run(self, ctx: RunContext) -> AdapterResult:
        cmd = f"graphw00f -d -t {ctx.target}"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="graphw00f not found")
        try:
            proc = self._exec(["graphw00f", "-d", "-f", "-t", ctx.target],
                              timeout=ctx.options.get("timeout", 300))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")
        findings = parse_graphw00f(proc.stdout)
        note = f"engine: {findings[0]['engine']}" if findings else "no GraphQL endpoint"
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd, note=note)


@register
class SchemathesisAdapter(ToolAdapter):
    name = "schemathesis"
    stage = "scan"
    discovers = False
    detects = True
    active = True
    binary = "schemathesis"

    def run(self, ctx: RunContext) -> AdapterResult:
        schema = ctx.options.get("openapi_schema")
        cmd = "schemathesis run <schema> --checks all"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="schemathesis not found")
        if not schema:
            return AdapterResult(tool=self.name, ok=True, command=cmd,
                                 note="no OpenAPI schema (not applicable)")
        args = ["schemathesis", "run", schema, "--checks", "all"]
        cookie = _cookie_header(ctx.session, ctx.target)
        if cookie:
            args += ["-H", f"Cookie: {cookie}"]
        try:
            proc = self._exec(args, timeout=ctx.options.get("timeout", 1200))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")
        # schemathesis text output; count failures.
        fails = len(re.findall(r"\bFAILED\b", proc.stdout))
        findings = [{"tool": "schemathesis", "category": "other"}] * fails
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{fails} api check failure(s)", raw=proc.stdout)
