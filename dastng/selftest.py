"""Parse-path self-test: prove every tool->parser path still works BEFORE a real scan, so a
silent parsing failure (e.g. a tool changes its output format on upgrade) can never masquerade
as a clean result.

It serves a tiny known-vulnerable canary locally, runs each tool + our probes against it, and
asserts the finding is detected AND parsed. If a canary that must be vulnerable comes back
clean, the parse path is broken -> the engagement halts loudly instead of under-reporting.

Also exposes parse_guard(): raw output present but 0 parsed records + no tool error == probable
format mismatch, flagged rather than trusted as 'nothing found'.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

# ----- parse guard ------------------------------------------------------------

def parse_guard(tool: str, raw: str, parsed_count: int, exit_code: int = 0,
                min_bytes: int = 40) -> str | None:
    """Return a warning string if the output looks unparsed (probable format mismatch),
    else None. A parser that yields 0 records is only trustworthy when the raw output is
    also (near-)empty and the tool did not error."""
    raw = raw or ""
    low = raw.lower()
    if exit_code not in (0, 1, 2) or "panic:" in low or "unknown flag" in low \
            or "unknown shorthand" in low or "no such option" in low:
        return f"{tool}: tool errored (exit {exit_code}) — result INCONCLUSIVE, not clean"
    if parsed_count == 0 and len(raw.strip()) > min_bytes:
        # output present but nothing parsed -> likely the format changed
        return (f"{tool}: {len(raw)} bytes of output but 0 records parsed — "
                f"PROBABLE FORMAT MISMATCH (parser may be stale)")
    return None


# ----- canary server ----------------------------------------------------------

class _Canary(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        path, body, code, headers = u.path, "", 200, {}
        if path == "/xss":
            val = (q.get("q") or [""])[0]
            body = f"<html><body>hello {val}</body></html>"      # reflect UNENCODED
        elif path == "/sqli":
            val = (q.get("id") or [""])[0]
            body = ("You have an error in your SQL syntax; check the manual"
                    if ("'" in val or '"' in val) else "ok")
        elif path == "/redirect":
            dest = (q.get("url") or [""])[0]
            if dest:
                code, headers = 302, {"Location": dest}
            body = "redirecting"
        elif path == "/lfi":
            val = (q.get("page") or [""])[0]
            body = ("root:x:0:0:root:/root:/bin/bash\n" if "passwd" in val else "ok")
        else:
            body = "canary"
        data = body.encode()
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class CanaryServer:
    def __init__(self):
        self.httpd = HTTPServer(("127.0.0.1", 0), _Canary)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"

    def __enter__(self):
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()


@dataclass
class SelfTestResult:
    check: str
    tool: str
    passed: bool
    detail: str


def run_selftest() -> list[SelfTestResult]:
    """Run each parse path against a canary that MUST be detected. A failure means the
    parser/tool is broken (not that the canary is safe)."""
    from .engagement import verify_lfi, verify_open_redirect, verify_reflected_xss, verify_sqli
    out: list[SelfTestResult] = []
    with CanaryServer() as c:
        b = c.base
        # our deterministic probes
        checks = [
            ("probe:xss", "probe", lambda: verify_reflected_xss(f"{b}/xss", "q", "GET", "")[0]),
            ("probe:sqli", "probe", lambda: verify_sqli(f"{b}/sqli", "id", "GET", "")[0]),
            ("probe:lfi", "probe", lambda: verify_lfi(f"{b}/lfi", "page", "GET", "")[0]),
            ("probe:open-redirect", "probe",
             lambda: verify_open_redirect(f"{b}/redirect", "url", "GET", "")[0]),
        ]
        for name, tool, fn in checks:
            try:
                ok = fn()
            except Exception as exc:  # noqa: BLE001
                out.append(SelfTestResult(name, tool, False, f"exception: {exc}")); continue
            out.append(SelfTestResult(name, tool, ok,
                                      "canary detected" if ok else "CANARY MISSED — parse/probe broken"))

        # dalfox production parser (the format-drift-prone one). Assert the PRODUCTION parser
        # (parse_dalfox) extracts the finding — not a fallback — so parser drift is caught.
        if shutil.which("dalfox"):
            from .orchestrator.adapters.dalfox import parse_dalfox
            try:
                p = subprocess.run(["dalfox", "url", "--url", f"{b}/xss?q=test", "-f", "jsonl",
                                    "-S"], capture_output=True, text=True, timeout=60, check=False)
                raw = p.stdout
                findings = parse_dalfox(raw)
                ok = len(findings) > 0
                guard = parse_guard("dalfox", raw, len(findings), p.returncode)
                detail = (f"parse_dalfox extracted {len(findings)} finding(s)" if ok
                          else (guard or "PARSER MISS: dalfox reported a vuln our parser did not extract"))
                out.append(SelfTestResult("dalfox:xss", "dalfox", ok, detail))
            except Exception as exc:  # noqa: BLE001
                out.append(SelfTestResult("dalfox:xss", "dalfox", False, f"exception: {exc}"))
    return out


def selftest_ok(results: list[SelfTestResult]) -> bool:
    return all(r.passed for r in results)
