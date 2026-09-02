"""OpenRedireX open-redirect adapter (detection, active).

Wraps devanshbatham/OpenRedireX — an async open-redirect fuzzer that carries a real
allowlist-BYPASS payload set (`//evil@good.com`, whitelisted-host-as-path, `%2f..`,
CRLF-in-redirect, etc.). It replaces each redirect-ish param value with each payload,
follows the redirect chain, and reports when the response actually redirects OFF-host to
the attacker URL. This is genuine capability for real client apps' naive/allowlist redirects,
NOT a target-specific hack.

Tool lives outside the venv (a git clone); point D4ST_OPENREDIREX at it (default
~/.d4st/tools/OpenRedireX). Payload file overridable via D4ST_OPENREDIREX_PAYLOADS.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from urllib.parse import parse_qs, urlsplit

from ._targets import candidate_urls
from .base import AdapterResult, RunContext, ToolAdapter, register

# Redirect-ish param names worth fuzzing (superset of the native probe's list).
_REDIR_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "redirecturl", "url", "uri", "next",
    "return", "returnurl", "return_url", "returnto", "return_to", "dest", "destination",
    "continue", "goto", "go", "out", "target", "to", "link", "forward", "callback",
    "checkout_url", "r", "u", "rurl", "redir", "view", "image_url", "domain",
}
# OpenRedireX's success line: "[FOUND] <url> redirects to <a> --> <b>"
_FOUND = re.compile(r"\[FOUND\]\s+(?P<url>\S+)\s+redirects to\s+(?P<chain>.+)$")


def _tool_dir() -> str:
    return os.environ.get("D4ST_OPENREDIREX",
                          os.path.expanduser("~/.d4st/tools/OpenRedireX"))


@register
class OpenRedireXAdapter(ToolAdapter):
    name = "openredirex"
    stage = "scan"
    detects = True
    active = True

    def available(self) -> bool:
        script = os.path.join(_tool_dir(), "openredirex.py")
        if not os.path.exists(script):
            return False
        try:
            import aiohttp  # noqa: F401
        except Exception:
            return False
        return True

    def run(self, ctx: RunContext) -> AdapterResult:
        script = os.path.join(_tool_dir(), "openredirex.py")
        payloads = os.environ.get("D4ST_OPENREDIREX_PAYLOADS",
                                  os.path.join(_tool_dir(), "payloads.txt"))
        # Only feed URLs that carry a redirect-ish param — everything else is noise for this tool.
        urls = candidate_urls(ctx.seed_urls) or ctx.seed_urls or []
        redir_urls = []
        for u in urls:
            q = parse_qs(urlsplit(u).query)
            if any(p.lower() in _REDIR_PARAMS for p in q):
                # put the FUZZ keyword in the redirect param(s) so the tool fuzzes the right slot
                redir_urls.append(_fuzzify(u))
        redir_urls = sorted(set(redir_urls))
        if not redir_urls:
            return AdapterResult(tool=self.name, ok=True, note="no redirect-ish params in frontier")

        cookie = (ctx.options or {}).get("cookie", "")
        conc = str(max(5, int((ctx.options or {}).get("workers", 10))))
        args = [sys.executable, script, "-p", payloads, "-k", "FUZZ", "-c", conc]
        # OpenRedireX has no cookie flag; carry auth by embedding it is not supported, so this
        # runs unauth (open redirect rarely needs auth). Feed the URL list on stdin.
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("\n".join(redir_urls)); _ = fh.name
        try:
            proc = self._exec(args, timeout=int((ctx.options or {}).get("timeout", 600)),
                              stdin="\n".join(redir_urls) + "\n")
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, note=f"exec error: {exc}")

        findings: list[dict] = []
        target_host = (urlsplit(ctx.target).hostname or "").lower()
        for line in (proc.stdout or "").splitlines():
            m = _FOUND.search(line.strip())
            if not m:
                continue
            url = m.group("url")
            chain = m.group("chain").strip()
            # Confirm it actually left the target host (real open redirect, not a same-site hop).
            if _redirects_offsite(chain, target_host):
                findings.append({
                    "type": "open-redirect", "category": "open-redirect",
                    "url": url.replace("FUZZ", ""),
                    "param": _redir_param(url),
                    "evidence": f"redirects off-site: {chain[:140]}",
                    "verified": True,
                })
        note = f"{len(findings)} open redirect(s) over {len(redir_urls)} redirect param(s)"
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=" ".join(args),
                             note=note)


def _fuzzify(url: str) -> str:
    """Replace the value of each redirect-ish param with the FUZZ keyword."""
    sp = urlsplit(url)
    parts = []
    for kv in sp.query.split("&"):
        if not kv:
            continue
        k = kv.split("=", 1)[0]
        parts.append(f"{k}=FUZZ" if k.lower() in _REDIR_PARAMS else kv)
    return f"{sp.scheme}://{sp.netloc}{sp.path}?{'&'.join(parts)}"


def _redir_param(url: str) -> str | None:
    for kv in urlsplit(url).query.split("&"):
        k = kv.split("=", 1)[0]
        if k.lower() in _REDIR_PARAMS:
            return k
    return None


def _redirects_offsite(chain: str, target_host: str) -> bool:
    """The final URL in the redirect chain is on a host other than the target (the payload's
    attacker host: google.com / example.com / evil.*)."""
    last = chain.split("-->")[-1].strip()
    h = (urlsplit(last).hostname or "").lower()
    if not h or not target_host:
        return False
    return h != target_host and not h.endswith("." + target_host)
