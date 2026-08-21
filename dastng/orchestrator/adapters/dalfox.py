"""dalfox XSS adapter (detection, active).

Runs dalfox over the frontier's parameterized URLs in one pass (file mode) and parses its
JSON PoC output. dalfox headless-verifies reflected/DOM XSS, so its hits are high-confidence.
"""

from __future__ import annotations

import json
import tempfile

from ._targets import candidate_urls
from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header


def _is_finding(o) -> bool:
    """A real dalfox finding, not the v3 'meta' summary line."""
    if not isinstance(o, dict) or "meta" in o:
        return False
    # finding objects carry at least one of these
    return any(k in o for k in ("type", "cwe", "param", "payload", "data", "message_str",
                                "inject_type", "evidence"))


def parse_dalfox(text: str) -> list[dict]:
    """dalfox JSON output across versions: v1 bare array of PoCs; v2 {"findings": [...]};
    v3 emits a JSONL stream where the first line is a {"meta": ...} summary followed by one
    JSON object per finding. Skip the meta line so it is not miscounted as a finding."""
    text = (text or "").strip()
    if not text:
        return []
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            return [o for o in obj if _is_finding(o)]
        if isinstance(obj, dict):
            if isinstance(obj.get("findings"), list):   # dalfox v2
                return [o for o in obj["findings"] if isinstance(o, dict)]
            return [obj] if _is_finding(obj) else []
    except json.JSONDecodeError:
        pass
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if _is_finding(o):
            out.append(o)
    return out


@register
class DalfoxAdapter(ToolAdapter):
    name = "dalfox"
    stage = "scan"
    discovers = False
    detects = True
    active = True
    binary = "dalfox"

    def run(self, ctx: RunContext) -> AdapterResult:
        targets = candidate_urls(ctx.seed_urls or [ctx.target], require_params=True,
                                 cap=ctx.options.get("inject_cap", 0))
        if not targets:
            return AdapterResult(tool=self.name, ok=True,
                                 note="no parameterized URLs to test")
        cmd = f"dalfox file <{len(targets)} urls> -f json"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd,
                                 note=f"dry-run over {len(targets)} url(s)")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd,
                                 note="dalfox binary not found on PATH")

        try:
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
                fh.write("\n".join(targets))
                list_path = fh.name
            # dalfox v2 CLI: -f json, --cookies (plural), -S silence.
            args = ["dalfox", "file", list_path, "-f", "json", "-S"]
            cookie = _cookie_header(ctx.session, ctx.target)
            if cookie:
                args += ["--cookies", cookie]
            proc = self._exec(args, timeout=ctx.options.get("timeout", 1800))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")

        findings = parse_dalfox(proc.stdout)
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{len(findings)} xss finding(s)", raw=proc.stdout)
