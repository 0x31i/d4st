"""Passive security checks — the hardened-app profile (headers, cookies, CORS, TLS hygiene).

On a real hardened target (like the ACME EHR) the findings are dominated by config/passive
issues, not blatant injection. This module inspects responses deterministically and flags the
exact classes a commercial DAST reports: HSTS, CSP, clickjacking, CORS, cookie flags,
cacheable-HTTPS, charset, referer leakage, path-relative CSS, server/version disclosure.

Deterministic + low-FP; no browser required. Findings are site-level (deduped by check).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_log = logging.getLogger("d4st.passive")

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


_CSP_DIRECTIVES = {
    "default-src", "script-src", "script-src-elem", "script-src-attr", "style-src",
    "style-src-elem", "style-src-attr", "img-src", "connect-src", "font-src", "object-src",
    "media-src", "frame-src", "child-src", "worker-src", "manifest-src", "prefetch-src",
    "frame-ancestors", "form-action", "base-uri", "navigate-to", "report-uri", "report-to",
    "sandbox", "upgrade-insecure-requests", "block-all-mixed-content", "require-trusted-types-for",
    "trusted-types", "plugin-types", "referrer", "require-sri-for",
}


def _parse_csp(csp: str) -> dict:
    out: dict = {}
    for part in csp.split(";"):
        toks = part.strip().split()
        if toks:
            out[toks[0].lower()] = [t.lower() for t in toks[1:]]
    return out


def analyze_csp(csp: str) -> list[tuple]:
    """Parse a PRESENT Content-Security-Policy and flag weak directives the way a commercial DAST
    does. Returns (check, detail, severity) tuples. Clickjacking is intentionally left to the
    dedicated X-Frame-Options/frame-ancestors check to avoid double-reporting."""
    d = _parse_csp(csp)
    out: list[tuple] = []
    unknown = [n for n in d if n not in _CSP_DIRECTIVES]
    if unknown:
        out.append(("csp-malformed", _MISCONFIG,
                    f"CSP contains invalid directive(s) that browsers will NOT enforce: "
                    f"{', '.join(sorted(unknown))[:120]}", "low"))

    def srcs(name: str):
        if name in d:
            return d[name]
        return d.get("default-src")  # None if neither present

    ss = srcs("script-src")
    if ss is None:
        out.append(("csp-allows-untrusted-script", _MISCONFIG,
                    "CSP defines no script-src or default-src — untrusted script execution is not "
                    "restricted (CSP fails to mitigate XSS)", "medium"))
    elif any(t in ("'unsafe-inline'", "'unsafe-eval'", "*", "http:", "https:", "data:") for t in ss) \
            and "'strict-dynamic'" not in ss:
        weak = [t for t in ss if t in ("'unsafe-inline'", "'unsafe-eval'", "*", "http:", "https:", "data:")]
        out.append(("csp-allows-untrusted-script", _MISCONFIG,
                    f"script-src permits untrusted execution ({' '.join(weak)[:80]}) — CSP may fail "
                    "to mitigate cross-site scripting", "medium"))

    st = srcs("style-src")
    if st is None:
        out.append(("csp-allows-untrusted-style", _MISCONFIG,
                    "CSP defines no style-src or default-src — untrusted style execution is not "
                    "restricted", "low"))
    elif any(t in ("'unsafe-inline'", "*") for t in st):
        out.append(("csp-allows-untrusted-style", _MISCONFIG,
                    "style-src allows untrusted styles ('unsafe-inline' or *) — enables style-based "
                    "data exfiltration", "low"))

    if "form-action" not in d:
        out.append(("csp-allows-form-hijacking", _MISCONFIG,
                    "CSP has no form-action directive — an injected form can post credentials to an "
                    "attacker-controlled URL (form hijacking)", "low"))

    # Clickjacking via a PRESENT-but-permissive frame-ancestors (an absent frame-ancestors is
    # handled by the X-Frame-Options/clickjacking check). Permitting any external origin (a host or
    # wildcard beyond 'self'/'none') means third parties can frame the page.
    fa = d.get("frame-ancestors")
    if fa is not None:
        externals = [s for s in fa if s not in ("'self'", "'none'")]
        if externals:
            out.append(("csp-allows-clickjacking", _MISCONFIG,
                        f"CSP frame-ancestors permits framing by external origins "
                        f"({' '.join(externals)[:80]}) — does not fully mitigate clickjacking", "low"))
    return out


def check_response(url: str, status: int, headers: dict, body: str,
                   set_cookies: list[str], cors_acao: str | None = None) -> list[PassiveFinding]:
    """headers: case-insensitive dict-ish (lowercased keys). set_cookies: raw Set-Cookie lines.
    cors_acao: the Access-Control-Allow-Origin returned when we sent Origin: https://evil.example
    (None if not probed)."""
    h = {k.lower(): v for k, v in headers.items()}
    out: list[PassiveFinding] = []

    def add(check, cat, detail, sev="low"):
        out.append(PassiveFinding(check=check, category=cat, url=url, detail=detail, severity=sev))

    # HSTS (only meaningful over HTTPS) — flag missing AND weak policies
    if _is_https(url):
        hsts = h.get("strict-transport-security", "")
        if not hsts:
            add("hsts-not-enforced", _MISCONFIG, "no Strict-Transport-Security header")
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            max_age = int(m.group(1)) if m else 0
            weak = []
            if not m:
                weak.append("no max-age directive")
            elif max_age < 15552000:  # < 180 days
                weak.append(f"max-age={max_age} (< 180 days)")
            if "includesubdomains" not in hsts.lower():
                weak.append("missing includeSubDomains")
            if weak:
                add("hsts-weak", _MISCONFIG, "weak HSTS policy: " + "; ".join(weak))

    # Clickjacking: neither X-Frame-Options nor CSP frame-ancestors
    csp = h.get("content-security-policy", "")
    if "x-frame-options" not in h and "frame-ancestors" not in csp.lower():
        add("clickjacking", _MISCONFIG, "no X-Frame-Options / CSP frame-ancestors (frameable)")

    # CSP: missing entirely, or present-but-weak (policy analysis)
    if "content-security-policy" not in h:
        add("csp-missing", _MISCONFIG, "no Content-Security-Policy header")
    else:
        for chk, cat, detail, sev in analyze_csp(h["content-security-policy"]):
            add(chk, cat, detail, sev)

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

    # MIME-sniffing protection
    if "x-content-type-options" not in h:
        add("no-nosniff", _MISCONFIG,
            "no X-Content-Type-Options: nosniff (browsers may MIME-sniff responses)")

    # Permissions-Policy (feature-policy) — restrict powerful browser features
    if "permissions-policy" not in h and "feature-policy" not in h:
        add("no-permissions-policy", _MISCONFIG,
            "no Permissions-Policy header (camera/mic/geolocation not restricted)")

    # Technology / version disclosure — .NET/IIS leaks these; fingerprints the stack for an attacker
    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        val = h.get(hdr, "")
        # only report when it discloses a VERSION or a specific product+version (bare "cloudflare"/"nginx"
        # with no version is low-signal noise; a version string or ASP.NET header is the real leak)
        if val and (hdr.startswith("x-aspnet") or any(ch.isdigit() for ch in val)):
            add(f"version-disclosure-{hdr}", _INFO,
                f"technology/version disclosed in '{hdr}: {val}' header")

    # Cacheable HTTPS response — a cookie-bearing OR HTML page over HTTPS that proxies/browsers may
    # cache (Burp's "Cacheable HTTPS response"). Static assets aside, an HTML app page or a
    # cookie-setting response cached by a shared proxy can leak sensitive content.
    cc = h.get("cache-control", "").lower()
    ct_cache = h.get("content-type", "").lower()
    cacheable = not any(x in cc for x in ("no-store", "no-cache", "private"))
    if _is_https(url) and cacheable and (set_cookies or "text/html" in ct_cache):
        why = "sets a cookie" if set_cookies else "HTML response"
        add("cacheable-https", _INFO,
            f"cacheable HTTPS response ({why}; Cache-Control: {cc or 'unset'})")

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

    # Cross-domain script include: a <script src> pulled from a third-party origin. Handles
    # absolute (http(s)://) AND protocol-relative (//host/…) URLs — the latter is common for CDNs
    # (e.g. //img1.wsimg.com/…) and was previously missed.
    page_host = urlsplit(url).hostname or ""
    for m in re.finditer(r'<script\b[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE):
        src = m.group(1)
        s = urlsplit(src)
        external = s.hostname and s.hostname != page_host and (
            s.scheme in ("http", "https") or src.startswith("//"))
        if external:
            add("cross-domain-script-include", _INFO,
                f"third-party script included from {s.hostname} ({src[:80]}) — page trusts "
                "code served by an external origin", sev="low")
            break

    # Mixed content: an HTTPS page pulling ACTIVE subresources over plaintext http://
    if _is_https(url) and "text/html" in h.get("content-type", "").lower():
        mixed = re.findall(
            r'<(?:script|link|iframe|img|source|audio|video)\b[^>]+(?:src|href)=["\']?(http://[^"\'>\s]+)',
            body, re.IGNORECASE)
        if mixed:
            add("mixed-content", _MISCONFIG,
                f"HTTPS page references {len(mixed)} plaintext http:// subresource(s), "
                f"e.g. {mixed[0][:120]}", sev="medium")

    return out


def _check_http_service(host: str, base_headers: dict) -> PassiveFinding | None:
    """Probe the plaintext http:// listener for a host. Flags a finding when the site serves
    content over cleartext HTTP without upgrading to HTTPS (Burp's 'Unencrypted communications').
    Returns None when http correctly 301/302-redirects to https, or the port is closed/errors."""
    import httpx
    url = f"http://{host}/"
    try:
        r = httpx.get(url, headers=base_headers, follow_redirects=False, timeout=10, verify=False)
    except Exception as e:  # noqa: BLE001
        _log.debug("cleartext probe failed for %s: %s", url, e)
        return None
    loc = r.headers.get("location", "") or ""
    if 300 <= r.status_code < 400 and loc.lower().startswith("https://"):
        return None  # plaintext listener correctly upgrades to HTTPS — not a finding
    # Any other cleartext response proves an unencrypted HTTP service is reachable (Burp's
    # "Unencrypted communications"). 2xx or a non-https redirect = actively serving over http
    # (medium); a 4xx/5xx still means the plaintext listener is up but isn't serving content (low).
    serving = r.status_code < 400
    sev = "medium" if serving else "low"
    if serving:
        detail = (f"service reachable over plaintext HTTP (status {r.status_code}"
                  + (f", redirects to {loc[:80]}" if loc else ", no HTTPS upgrade") + ")")
    else:
        detail = (f"plaintext HTTP listener reachable (status {r.status_code}) — an unencrypted "
                  "service is exposed even though it does not serve content on this path")
    proof = {
        "label": "plaintext HTTP response",
        "request": {"method": "GET", "url": url, "headers": {}, "body": ""},
        "response": {"status": r.status_code, "headers": dict(r.headers),
                     "elapsed_ms": None, "size": len(r.text or ""),
                     "body": (r.text or "")[:4000], "truncated": len(r.text or "") > 4000},
    }
    return PassiveFinding(check="cleartext-service", category=_MISCONFIG, url=url,
                          detail=detail, severity=sev, response=proof)


def passive_scan(urls: list[str], cookie: str, cap: int = 40) -> list[PassiveFinding]:
    """Fetch a sample of discovered URLs and run passive checks. Dedups by (check, host)."""
    import httpx

    from .safety import browser_headers
    headers = browser_headers({"Cookie": cookie} if cookie else None)
    seen: set = set()
    http_probed: set = set()
    out: list[PassiveFinding] = []
    for url in urls[:cap]:
        host = urlsplit(url).hostname or ""
        # Once per host: is the plaintext HTTP service reachable without upgrading to HTTPS?
        if host and host not in http_probed:
            http_probed.add(host)
            hf = _check_http_service(host, headers)
            if hf and ("cleartext-service", host) not in seen:
                seen.add(("cleartext-service", host))
                out.append(hf)
        try:
            # verify=False: pentest targets routinely have invalid/self-signed certs (the target may
            # even BE the cert finding). Without this, every HTTPS fetch raises an SSLError that the
            # except below swallows — silently dropping ALL passive header findings on such hosts.
            r = httpx.get(url, headers=headers, follow_redirects=True, timeout=12, verify=False)
            # CORS probe: does the server reflect an evil Origin?
            cr = httpx.get(url, headers={**headers, "Origin": "https://evil.example"},
                           follow_redirects=True, timeout=12, verify=False)
            acao = cr.headers.get("access-control-allow-origin")
        except Exception as e:  # noqa: BLE001, S112
            _log.debug("passive fetch failed for %s: %s", url, e)
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
