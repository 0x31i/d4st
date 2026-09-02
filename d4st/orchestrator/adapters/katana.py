"""katana crawl adapter (blind authenticated discovery).

Crawls from the target with the captured session, JS-aware, and CRUCIALLY excludes logout
(and setup/reset) URLs via crawl-out-scope so it does not destroy its own session mid-crawl
(the DVWA/OCWA logout-link trap). Emits discovered URLs to the frontier.
"""

from __future__ import annotations

from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _session_header_args

# Never crawl these: logging out kills the session; setup/reset wipes app state.
_LOGOUT_OUT_OF_SCOPE = r"logout|signout|sign-out|/setup|reset"


@register
class KatanaAdapter(ToolAdapter):
    name = "katana"
    stage = "crawl"
    discovers = True
    detects = False
    active = False
    binary = "katana"

    def run(self, ctx: RunContext) -> AdapterResult:
        depth = str(ctx.options.get("crawl_depth", 3))
        duration = str(ctx.options.get("crawl_duration", "3m"))
        # NOTE: plain-text output (one URL per line). katana's -json emits a single JSON
        # array, not JSON-Lines, which trips line-based parsing; we extract forms separately.
        args = ["katana", "-u", ctx.target, "-jc", "-silent",
                "-d", depth, "-ct", duration,
                "-cos", _LOGOUT_OUT_OF_SCOPE,   # crawl-out-scope: skip logout/setup
                "-fs", "fqdn",                   # stay on the target host
                "-kf", "all",                    # known-files (robots, sitemap)
                "-c", str(ctx.options.get("crawl_concurrency", 10))]
        args += _session_header_args(ctx.session, ctx.target)
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
            if line.startswith("http"):
                urls.append(line)

        return AdapterResult(
            tool=self.name,
            ok=proc.returncode == 0,
            discovered_urls=urls,
            command=cmd,
            note=f"{len(urls)} urls discovered",
            raw=proc.stdout,
        )
