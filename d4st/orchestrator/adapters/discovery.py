"""Discovery adapters that feed the shared frontier: feroxbuster (recursive content),
gau (historical URLs), x8 (hidden parameters). All are non-active (recon).
"""

from __future__ import annotations

import json

from ._targets import candidate_urls
from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header


def parse_feroxbuster(text: str) -> list[str]:
    """feroxbuster --json emits JSONL; keep response URLs with status < 400."""
    urls: list[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if o.get("type") == "response" and o.get("url"):
            status = o.get("status", 0)
            if isinstance(status, int) and 0 < status < 400:
                urls.append(o["url"])
    return urls


def parse_gau(text: str) -> list[str]:
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip().startswith("http")]


def parse_x8(text: str) -> list[dict]:
    """x8 -O json emits found parameters. Return [{url, param}]."""
    text = (text or "").strip()
    if not text:
        return []
    out: list[dict] = []
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return out
    rows = obj if isinstance(obj, list) else obj.get("results", obj.get("found", []))
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        url = r.get("url") or r.get("request_url") or ""
        for p in r.get("found_params", r.get("params", [])) or []:
            name = p.get("name") if isinstance(p, dict) else p
            if name:
                out.append({"url": url, "param": name})
    return out


@register
class FeroxbusterAdapter(ToolAdapter):
    name = "feroxbuster"
    stage = "recon"
    discovers = True
    detects = False
    active = False
    binary = "feroxbuster"

    def run(self, ctx: RunContext) -> AdapterResult:
        cmd = f"feroxbuster -u {ctx.target} --json -q"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="feroxbuster not found")
        # Real-world content discovery: default to the standard SecLists common.txt (~4.7k
        # entries seen in actual engagements) so hits are legitimate, not app-tailored. Falls
        # back to raft-medium, then a small generic supplement. Override via options.
        import os
        _root = os.path.join(os.path.dirname(__file__), "..", "..", "..")
        wl = ctx.options.get("ferox_wordlist")
        if not wl:
            for cand in (os.path.join(_root, "vendor", "seclists", "common.txt"),
                         os.path.join(_root, "vendor", "seclists", "raft-medium-directories.txt"),
                         os.path.join(os.path.dirname(__file__), "..", "..", "wordlists",
                                      "content-discovery.txt")):
                if os.path.exists(cand):
                    wl = cand
                    break
        # NB: `--json -q` emits nothing (quiet suppresses the JSON stream). `--json -o
        # /dev/stdout` routes JSONL results to stdout. feroxbuster auto-filters the SPA
        # catch-all (404-like wildcard) itself, so real resources (/ftp, /metrics) survive.
        args = ["feroxbuster", "-u", ctx.target, "--json", "-o", "/dev/stdout", "--no-state",
                "-d", str(ctx.options.get("ferox_depth", 2)),
                # Throttle: feroxbuster's default 50 threads DoSes fragile targets. The safe
                # profile passes ferox_threads/ferox_rate so content discovery stays gentle.
                "-t", str(ctx.options.get("ferox_threads", 10)),
                # Native adaptive safety (feroxbuster's own circuit breakers) so content
                # discovery self-protects even before the rate cap: --auto-tune lowers the scan
                # rate when it detects errors/timeouts; --auto-bail aborts if the error rate
                # spikes (target struggling). This gives feroxbuster the same detect-stress ->
                # back-off -> bail behavior the TargetHealth monitor gives the rest of the scan.
                "--auto-tune", "--auto-bail"]
        _rate = ctx.options.get("ferox_rate")
        if _rate:
            args += ["--rate-limit", str(_rate)]
        if os.path.exists(os.path.expanduser(wl)):
            args += ["-w", os.path.expanduser(wl)]
        cookie = _cookie_header(ctx.session, ctx.target) or (ctx.options.get("cookie") or "")
        if cookie:
            args += ["-H", f"Cookie: {cookie}"]
        try:
            proc = self._exec(args, timeout=ctx.options.get("timeout", 900))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")
        urls = parse_feroxbuster(proc.stdout)
        return AdapterResult(tool=self.name, ok=True, discovered_urls=urls, command=cmd,
                             note=f"{len(urls)} paths", raw=proc.stdout)


@register
class GauAdapter(ToolAdapter):
    name = "gau"
    stage = "recon"
    discovers = True
    detects = False
    active = False
    binary = "gau"

    def run(self, ctx: RunContext) -> AdapterResult:
        from urllib.parse import urlsplit
        host = urlsplit(ctx.target).hostname or ctx.target
        cmd = f"gau {host}"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="gau not found")
        try:
            proc = self._exec(["gau", "--threads", "5", host],
                              timeout=ctx.options.get("timeout", 300))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")
        urls = parse_gau(proc.stdout)
        return AdapterResult(tool=self.name, ok=True, discovered_urls=urls, command=cmd,
                             note=f"{len(urls)} historical urls", raw=proc.stdout)


@register
class X8Adapter(ToolAdapter):
    name = "x8"
    stage = "recon"
    discovers = True
    detects = False
    active = False
    binary = "x8"

    def run(self, ctx: RunContext) -> AdapterResult:
        targets = candidate_urls(ctx.seed_urls or [ctx.target], require_params=False,
                                 cap=ctx.options.get("x8_cap", 25))
        cmd = f"x8 -u <{len(targets)} urls> -O json"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="x8 not found")
        args = ["x8", "-u", *targets, "-O", "json"]
        cookie = _cookie_header(ctx.session, ctx.target)
        if cookie:
            args += ["-H", f"Cookie: {cookie}"]
        try:
            proc = self._exec(args, timeout=ctx.options.get("timeout", 900))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")
        params = parse_x8(proc.stdout)
        urls = sorted({p["url"] for p in params if p.get("url")})
        return AdapterResult(tool=self.name, ok=True, discovered_urls=urls, findings=params,
                             command=cmd, note=f"{len(params)} hidden param(s)", raw=proc.stdout)
