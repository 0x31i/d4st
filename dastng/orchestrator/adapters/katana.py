"""katana crawl adapter (discovery). Reference implementation of a DISCOVER adapter.

Full authenticated-crawl flag wiring (headers from the captured session, depth, JS parsing)
lands in Phase 2. Here it establishes the shape: shell out, parse JSONL, feed the frontier.
"""

from __future__ import annotations

import json

from .base import AdapterResult, RunContext, ToolAdapter, register


@register
class KatanaAdapter(ToolAdapter):
    name = "katana"
    stage = "crawl"
    discovers = True
    detects = False
    active = False
    binary = "katana"

    def run(self, ctx: RunContext) -> AdapterResult:
        args = ["katana", "-u", ctx.target, "-jc", "-silent", "-json"]
        # Phase 1 will inject: -H "Cookie: ..." / -H "Authorization: ..." from ctx.session.
        cmd = " ".join(args)

        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run (not executed)")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd,
                                 note="katana binary not found on PATH")

        try:
            proc = self._exec(args, timeout=ctx.options.get("timeout", 900))
        except Exception as exc:  # noqa: BLE001 - adapters never raise
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")

        urls: list[str] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            u = obj.get("endpoint") or obj.get("url") or (obj.get("request") or {}).get("endpoint")
            if u:
                urls.append(u)

        return AdapterResult(
            tool=self.name,
            ok=proc.returncode == 0,
            discovered_urls=urls,
            command=cmd,
            note=f"{len(urls)} urls discovered",
            raw=proc.stdout,
        )
