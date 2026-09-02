"""Passive security checks — the hardened-app profile (headers, cookies, CORS, TLS hygiene).

On a real hardened target (like the FHC EHR) the findings are dominated by config/passive
issues, not blatant injection. This module inspects responses deterministically and flags the
exact classes a commercial DAST reports: HSTS, CSP, clickjacking, CORS, cookie flags,
cacheable-HTTPS, charset, referer leakage, path-relative CSS, server/version disclosure.

Deterministic + low-FP; no browser required. Findings are site-level (deduped by check).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_MISCONFIG = "misconfiguration"
_INFO = "info-disclosure"


@dataclass
class PassiveFinding:
    check: str
    category: str
    url: str
    detail: str
    severity: str = "low"
    response: dict = None      # the request/response that demonstrates the issue (proof)


def _is_https(url: str) -> bool:
    return urlsplit(url).scheme == "https"


def check_response(url: str, status: int, headers: dict, body: str,
                   set_cookies: list[str], cors_acao: str | None = None) -> list[PassiveFinding]:
    """headers: case-insensitive dict-ish (lowercased keys). set_cookies: raw Set-Cookie lines.
    cors_acao: the Access-Control-Allow-Origin returned when we sent Origin: https://evil.example
    (None if not probed)."""
    h = {k.lower(): v for k, v in headers.items()}
    out: list[PassiveFinding] = []

    def add(check, cat, detail, sev="low"):
        out.append(PassiveFinding(check=check, category=cat, url=url, detail=detail, severity=sev))

    # HSTS (only meaningful over HTTPS)
    if _is_https(url) and "strict-transport-security" not in h:
        add("hsts-not-enforced", _MISCONFIG, "no Strict-Transport-Security header")

    # Clickjacking: neither X-Frame-Options nor CSP frame-ancestors
    csp = h.get("content-security-policy", "")
    if "x-frame-options" not in h and "frame-ancestors" not in csp.lower():
        add("clickjacking", _MISCONFIG, "no X-Frame-Options / CSP frame-ancestors (frameable)")

    # CSP missing
    if "content-security-policy" not in h:
        add("csp-missing", _MISCONFIG, "no Content-Security-Policy header")

    # CORS: server reflects an arbitrary Origin, or wildcards with credentials
    if cors_acao is not None:
        acac = h.get("access-control-allow-credentials", "").lower()
        if "evil.example" in cors_acao:
            add("cors-misconfig", _MISCONFIG,
                f"Access-Control-Allow-Origin reflects arbitrary origin ({cors_acao})",
                sev="medium")
        elif cors_acao == "*" and acac == "true":
            add("cors-misconfig", _MISCONFIG, "ACAO=* with credentials allowed", sev="medium")

    # Cookie flags (over HTTPS)
    for c in set_cookies:
        cl = c.lower()
        name = c.split("=", 1)[0].strip()
        if _is_https(url) and "secure" not in cl:
            add("cookie-no-secure", _MISCONFIG, f"cookie {name} without Secure flag")
        if "httponly" not in cl:
            add("cookie-no-httponly", _MISCONFIG, f"cookie {name} without HttpOnly flag")
        if "samesite" not in cl:
            add("cookie-no-samesite", _MISCONFIG, f"cookie {name} without SameSite attribute")

    # Referrer-Policy (cross-domain referer leakage)
    if "referrer-policy" not in h:
        add("referer-leakage", _MISCONFIG, "no Referrer-Policy (cross-domain referer leakage)")

    # Cacheable HTTPS response with a session-ish cookie present
    cc = h.get("cache-control", "").lower()
    if _is_https(url) and set_cookies and not any(x in cc for x in ("no-store", "no-cache", "private")):
        add("cacheable-https", _INFO, f"cacheable HTTPS response (Cache-Control: {cc or 'unset'})")

    # HTML without charset
    ct = h.get("content-type", "").lower()
    if "text/html" in ct and "charset=" not in ct and not re.search(r'charset=', body[:2048], re.IGNORECASE):
        add("no-charset", _MISCONFIG, "HTML response does not specify a charset")

    # Server / tech version disclosure
    server = h.get("server", "")
    if re.search(r"\d", server):
        add("version-disclosure", _INFO, f"Server header discloses version: {server}")
    if "x-powered-by" in h:
        add("version-disclosure", _INFO, f"X-Powered-By: {h['x-powered-by']}")

    # Path-relative stylesheet import (breaks under path-based cache poisoning)
    for m in re.finditer(r'<link[^>]+rel=["\']?stylesheet["\']?[^>]*>', body, re.IGNORECASE):
        href = re.search(r'href=["\']([^"\']+)["\']', m.group(0), re.IGNORECASE)
        if href and not href.group(1).startswith(("/", "http", "//", "data:")):
            add("path-relative-css", _MISCONFIG, f"path-relative stylesheet import: {href.group(1)}")
            break

    return out


def passive_scan(urls: list[str], cookie: str, cap: int = 40) -> list[PassiveFinding]:
    """Fetch a sample of discovered URLs and run passive checks. Dedups by (check, host)."""
    import httpx
    headers = {"Cookie": cookie} if cookie else {}
    seen: set = set()
    out: list[PassiveFinding] = []
    for url in urls[:cap]:
        host = urlsplit(url).hostname or ""
        try:
            r = httpx.get(url, headers=headers, follow_redirects=True, timeout=12)
            # CORS probe: does the server reflect an evil Origin?
            cr = httpx.get(url, headers={**headers, "Origin": "https://evil.example"},
                           follow_redirects=True, timeout=12)
            acao = cr.headers.get("access-control-allow-origin")
        except Exception:  # noqa: BLE001, S112
            continue
        set_cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []
        # The response IS the proof for a passive finding (the headers that are missing/present).
        _elapsed = None
        try:
            _elapsed = round(r.elapsed.total_seconds() * 1000)
        except Exception:  # noqa: BLE001
            _elapsed = None
        _proof = {
            "label": "observed response",
            "request": {"method": "GET", "url": str(r.url),
                        "headers": {"Cookie": "[redacted]"} if cookie else {}, "body": ""},
            "response": {"status": r.status_code, "headers": dict(r.headers),
                         "elapsed_ms": _elapsed, "size": len(r.text or ""),
                         "body": (r.text or "")[:8000], "truncated": len(r.text or "") > 8000},
        }
        for f in check_response(str(r.url), r.status_code, dict(r.headers), r.text,
                                set_cookies, cors_acao=acao):
            key = (f.check, host)
            if key in seen:
                continue
            seen.add(key)
            f.response = _proof
            out.append(f)
    return out
