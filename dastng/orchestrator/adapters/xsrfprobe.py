"""XSRFProbe CSRF adapter (detection, active).

Wraps 0xInfection/XSRFProbe — a dedicated CSRF audit toolkit. It crawls the target, finds
forms + state-changing endpoints, and reports missing / weak / low-entropy anti-CSRF tokens
(the closest standalone equivalent to Burp's CSRF check). This is the form-based detector;
the JSON-API / SPA case is covered by the native SPA-CSRF heuristic in the response pipeline.

XSRFProbe's `tld` dependency rejects non-public-TLD hosts (localhost / bare IPs) and raises —
so on such targets (test rigs) this adapter cleanly no-ops with a note; real client domains run.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
from urllib.parse import urlsplit

from .base import AdapterResult, RunContext, ToolAdapter, register


def _xsrfprobe_bin() -> str | None:
    """Locate the xsrfprobe console script. It installs next to the running interpreter
    (.venv/bin), which is not necessarily on PATH when the engagement runs as
    `.venv/bin/python ...`, so check there before falling back to PATH."""
    cand = os.path.join(os.path.dirname(sys.executable), "xsrfprobe")
    if os.path.exists(cand):
        return cand
    return shutil.which("xsrfprobe")

# XSRFProbe prints its verdict per endpoint; these mark a real CSRF weakness.
_VULN = re.compile(
    r"(No Anti-CSRF Tokens|Very Short/No Anti-CSRF|No CSRF (?:protection|token)|"
    r"Vulnerable to CSRF|Token not (?:found|present)|nonced?.{0,20}not|CSRF Vulnerabilit)",
    re.I)
_URLCTX = re.compile(r"https?://\S+")


def _has_public_tld(url: str) -> bool:
    try:
        from tld import get_tld
        return get_tld(url, fail_silently=True) is not None
    except Exception:
        # if the tld lib is unhappy, assume runnable and let the tool decide
        host = (urlsplit(url).hostname or "")
        return "." in host and not host.replace(".", "").isdigit()


@register
class XSRFProbeAdapter(ToolAdapter):
    name = "xsrfprobe"
    stage = "scan"
    detects = True
    active = True
    binary = "xsrfprobe"

    def available(self) -> bool:
        return _xsrfprobe_bin() is not None

    def run(self, ctx: RunContext) -> AdapterResult:
        if not _has_public_tld(ctx.target):
            return AdapterResult(
                tool=self.name, ok=False,
                note="skipped: XSRFProbe needs a public-TLD host (localhost/IP unsupported); "
                     "real client domains run. SPA-CSRF heuristic still covers this target.")
        outdir = tempfile.mkdtemp(prefix="xsrfprobe-", dir=ctx.workdir or None)
        cookie = (ctx.options or {}).get("cookie", "")
        args = [_xsrfprobe_bin(), "-u", ctx.target, "--crawl", "--no-analysis",
                "-o", outdir, "-t", str(int((ctx.options or {}).get("http_timeout", 15)))]
        if cookie:
            args += ["--cookie", cookie]
        try:
            proc = self._exec(args, timeout=int((ctx.options or {}).get("timeout", 900)))
        except Exception as exc:  # noqa: BLE001 - never sink the roster
            return AdapterResult(tool=self.name, ok=False, note=f"exec error: {exc}")

        findings: list[dict] = []
        last_url = ctx.target
        for line in (proc.stdout or "").splitlines():
            m = _URLCTX.search(line)
            if m:
                last_url = m.group(0).rstrip(".,)")
            if _VULN.search(line):
                findings.append({
                    "type": "csrf", "category": "csrf",
                    "url": last_url,
                    "evidence": f"XSRFProbe: {line.strip()[:140]}",
                    "verified": True,
                })
        # Also read XSRFProbe's written report dir (it logs vulnerable endpoints to files).
        findings += _parse_outdir(outdir)
        # dedup by url
        seen, uniq = set(), []
        for f in findings:
            k = (f.get("url"), f.get("category"))
            if k in seen:
                continue
            seen.add(k); uniq.append(f)
        return AdapterResult(tool=self.name, ok=True, findings=uniq, command=" ".join(args),
                             note=f"{len(uniq)} CSRF finding(s)")


def _parse_outdir(outdir: str) -> list[dict]:
    """XSRFProbe writes results under <outdir>/<domain>/; scoop any 'vulnerable'/'csrf' log
    lines that name an endpoint. Best-effort — the tool's file layout varies by version."""
    out: list[dict] = []
    try:
        for root, _dirs, files in os.walk(outdir):
            for fn in files:
                if not re.search(r"vuln|csrf|result|scan", fn, re.I):
                    continue
                try:
                    with open(os.path.join(root, fn), encoding="utf-8", errors="ignore") as fh:
                        for ln in fh:
                            u = _URLCTX.search(ln)
                            if u and _VULN.search(ln):
                                out.append({"type": "csrf", "category": "csrf",
                                            "url": u.group(0).rstrip(".,)"),
                                            "evidence": f"XSRFProbe report: {ln.strip()[:140]}",
                                            "verified": True})
                except Exception:  # noqa: BLE001,S112
                    continue
    except Exception:  # noqa: BLE001
        pass
    return out
