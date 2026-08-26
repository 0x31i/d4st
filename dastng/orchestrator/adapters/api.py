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
    # Weak/cracked signing secret (offline HMAC crack): "[+] secret123 is the CORRECT key!"
    for m in re.finditer(r"(?:^|\s)(\S+)\s+is the CORRECT key", text):
        out.append({"tool": "jwt_tool", "issue": "weak-hmac-secret", "category": "auth",
                    "evidence": f"signing secret cracked: {m.group(1)!r}"})
    # Playbook (-M at) exploit hits + classic algorithm/kid/injection issues.
    for rx, issue in (
        (r"alg[:=]?\s*none|None Algorithm|Exploit:\s*alg.*none", "alg-none"),
        (r"key confusion|RS/?HS|algorithm confusion", "key-confusion"),
        (r"kid.*(injection|traversal|sql)", "kid-injection"),
        (r"\bCVE-\d{4}-\d+\b", "known-cve"),
        (r"Signature (?:exclusion|not checked)|accepted (?:the )?tampered", "sig-not-verified"),
    ):
        m = re.search(rx, text, re.IGNORECASE)
        if m:
            out.append({"tool": "jwt_tool", "issue": issue, "category": "auth",
                        "evidence": m.group(0)[:80]})
    return out


def parse_schemathesis(text: str) -> list[dict]:
    """Modern schemathesis prints a summary ('N unique failures') + a per-category breakdown
    ('Response violates schema: 11'), NOT the old per-test 'FAILED' lines. Emit one finding per
    failure CATEGORY (with its count) so 24 raw failures become a handful of actionable rows."""
    text = _ANSI.sub("", text or "")
    out: list[dict] = []
    # per-category breakdown lines: "<X> Response violates schema: 11"
    for label, cnt in re.findall(r'(?:❌|X|\*)\s*([A-Z][^:\n]{3,60}?):\s*(\d+)\s*$',
                                 text, re.MULTILINE):
        out.append({"tool": "schemathesis", "category": "api-contract",
                    "issue": label.strip(), "count": int(cnt),
                    "evidence": f"{cnt} occurrence(s)"})
    if out:
        return out
    # fallback: the summary total, then the legacy FAILED lines
    m = re.search(r'(\d+)\s+(?:unique )?failures?\b', text)
    n = int(m.group(1)) if m else len(re.findall(r'\bFAILED\b', text))
    return [{"tool": "schemathesis", "category": "api-contract"}] * n


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

    # High-signal common JWT signing secrets — an HMAC token signed with any of these is trivially
    # forgeable (auth bypass). Offline crack, no target needed.
    _COMMON_SECRETS = (
        "secret", "jwt_secret", "jwtsecret", "secretkey", "secret_key", "password", "changeme",
        "key", "admin", "your-256-bit-secret", "supersecret", "super_secret", "private", "token",
        "qwerty", "letmein", "random", "mysecret", "s3cr3t", "test", "dev", "12345", "1234567890",
    )

    def run(self, ctx: RunContext) -> AdapterResult:
        token = ctx.options.get("jwt")
        cmd = "jwt_tool <token> -C -d <secrets>  (+ -M at -t <url> if endpoint known)"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="jwt_tool not found")
        if not token or token.count(".") != 2:
            return AdapterResult(tool=self.name, ok=True, command=cmd,
                                 note="no JWT provided (not applicable)")
        import os
        import tempfile
        findings: list[dict] = []
        to = ctx.options.get("timeout", 300)
        # (1) offline HMAC secret crack against common weak secrets (deterministic, no target).
        wl = ctx.options.get("jwt_wordlist")
        _tmp = None
        if not wl:
            fd, wl = tempfile.mkstemp(prefix="jwtwl_", suffix=".txt")
            os.write(fd, "\n".join(self._COMMON_SECRETS).encode())
            os.close(fd)
            _tmp = wl
        try:
            proc = self._exec(["jwt_tool", token, "-C", "-d", wl], timeout=to)
            findings += parse_jwt_tool(proc.stdout)
        except Exception:  # noqa: BLE001,S110
            pass
        # (2) active exploitation playbook, only if a JWT-validating endpoint is known (the tool
        # needs -t <url> to confirm alg:none / tampering acceptance — it cannot 'scan offline').
        tgt = ctx.options.get("jwt_target")
        if tgt:
            try:
                proc2 = self._exec(["jwt_tool", token, "-t", tgt, "-rh",
                                    f"Authorization: Bearer {token}", "-M", "at"], timeout=to)
                findings += parse_jwt_tool(proc2.stdout)
            except Exception:  # noqa: BLE001,S110
                pass
        if _tmp:
            try:
                os.unlink(_tmp)
            except OSError:
                pass
        # de-dup by issue
        seen, uniq = set(), []
        for f in findings:
            if f["issue"] not in seen:
                seen.add(f["issue"])
                uniq.append(f)
        return AdapterResult(tool=self.name, ok=True, findings=uniq, command=cmd,
                             note=f"{len(uniq)} jwt issue(s)")


@register
class Graphw00fAdapter(ToolAdapter):
    name = "graphw00f"
    stage = "recon"
    discovers = False
    detects = True
    active = False
    binary = "graphw00f"

    def run(self, ctx: RunContext) -> AdapterResult:
        # Prefer a GraphQL endpoint discovered by the API-surface stage; fall back to the target.
        gql = ctx.options.get("graphql_endpoint") or ctx.target
        cmd = f"graphw00f -d -t {gql}"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="graphw00f not found")
        try:
            proc = self._exec(["graphw00f", "-d", "-f", "-t", gql],
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
        cookie = _cookie_header(ctx.session, ctx.target) or ctx.options.get("cookie")
        if cookie:
            args += ["-H", f"Cookie: {cookie}"]
        if ctx.options.get("jwt"):     # carry bearer auth so authenticated operations are tested
            args += ["-H", f"Authorization: Bearer {ctx.options['jwt']}"]
        try:
            proc = self._exec(args, timeout=ctx.options.get("timeout", 1200))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")
        findings = parse_schemathesis(proc.stdout)
        total = sum(f.get("count", 1) for f in findings)
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{total} api-contract failure(s) in {len(findings)} categorie(s)",
                             raw=proc.stdout)
