"""Active depth tests that share one httpx client + the shared evidence shape:

  - run_cors_checks()   : turn "CORS present" noise into a VERIFIED exploitable/benign verdict —
                          does the server reflect an arbitrary Origin AND allow credentials?
  - run_verb_tampering(): method/verb-based access-control gaps (BFLA). SAFE by default — only
                          read-ish methods (OPTIONS/HEAD + method/case variants on ALREADY-protected
                          endpoints to catch verb-tampering auth bypass). Write-method probing
                          (POST/PUT/DELETE) is OPT-IN via D4ST_METHOD_TAMPER_WRITES=1 (never mutates
                          client data by default).
  - assess_secrets()    : elevate a disclosed key from "found" to scoped impact. Static classification
                          by default; a live restriction check runs only under D4ST_SECRET_VALIDATE=1.

All read-only unless explicitly opted in; throttled; every finding carries full evidence + repro.
"""

from __future__ import annotations

import os
import re
import time
from urllib.parse import urlsplit

from .evidence import curl, exchange, synthetic_exchange

_EVIL_ORIGIN = "https://d4st-cors-probe.example.org"


def _auth_header_name(session) -> str:
    for k in getattr(session, "headers", {}) or {}:
        if k.lower() == "authorization":
            return k
    return "Authorization"


def _authed_headers(session, base: str) -> dict:
    h = dict(getattr(session, "headers", {}) or {})
    try:
        ck = session.cookie_header(base)
        if ck:
            h["Cookie"] = ck
    except Exception:  # noqa: BLE001
        pass
    return h


# ---------------------------------------------------------------- CORS ----
def run_cors_checks(session, base: str, urls: list[str], *,
                    delay: float = 0.15, timeout: float = 12.0, max_urls: int = 25,
                    throttle=None) -> list[dict]:
    """Send a cross-origin request with an attacker Origin and judge the CORS response. Reflecting
    an arbitrary Origin WITH Access-Control-Allow-Credentials:true is exploitable (any site can read
    the victim's authenticated responses). ACAO:* is weaker (no creds). One consolidated finding."""
    import httpx

    from .safety import pace

    origin = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"
    cand = [u for u in urls if u.startswith(origin) and "/api/" in u.lower()] or \
           [u for u in urls if u.startswith(origin)]
    cand = cand[:max_urls]
    if not cand:
        return []

    authed = _authed_headers(session, base)
    findings: list[dict] = []
    reflected: list[tuple[str, object]] = []
    null_ok: list[tuple[str, object]] = []
    wildcard_creds: list[tuple[str, object]] = []

    with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as c:
        for u in cand:
            for test_origin in (_EVIL_ORIGIN, "null"):
                try:
                    r = c.get(u, headers={**authed, "Origin": test_origin})
                    pace(throttle, delay, r.status_code)
                except Exception:  # noqa: BLE001
                    continue
                acao = r.headers.get("access-control-allow-origin", "")
                acac = (r.headers.get("access-control-allow-credentials", "") or "").lower() == "true"
                if acao == test_origin and test_origin == _EVIL_ORIGIN:
                    reflected.append((u, r))
                    if acac:
                        wildcard_creds.append((u, r))
                elif acao == "null" and test_origin == "null":
                    null_ok.append((u, r))
                elif acao == "*" and acac:
                    wildcard_creds.append((u, r))
            if reflected and wildcard_creds:
                break  # enough proof

    def _mk(kind, sev, sample, detail):
        u, r = sample
        return {
            "type": kind, "name": kind, "severity": sev, "url": u, "method": "GET",
            "category": "cors-misconfiguration", "verified": True,
            "detail": detail,
            "evidence_log": [exchange("Cross-origin request with attacker Origin — server response "
                                      "reflects it", r)],
            "repro": curl(r),
        }

    if wildcard_creds:
        u, r = wildcard_creds[0]
        findings.append(_mk(
            "cors-credentialed-reflection", "high", (u, r),
            f"the server reflects an arbitrary Origin ('{_EVIL_ORIGIN}' or '*') AND returns "
            f"Access-Control-Allow-Credentials: true on {len(wildcard_creds)} endpoint(s). Any "
            f"attacker-controlled website can issue authenticated cross-origin requests and READ the "
            f"victim's responses — a genuine exploitable CORS misconfiguration (not the benign "
            f"'header present' that a naive scan reports)."))
    elif reflected:
        u, r = reflected[0]
        findings.append(_mk(
            "cors-origin-reflection", "medium", (u, r),
            f"the server reflects an arbitrary request Origin in Access-Control-Allow-Origin on "
            f"{len(reflected)} endpoint(s) WITHOUT allow-credentials. Lower impact (no cookie/cred "
            f"read) but still allows cross-origin reads of any non-credentialed response."))
    elif null_ok:
        u, r = null_ok[0]
        findings.append(_mk(
            "cors-null-origin", "medium", (u, r),
            "the server allows the 'null' Origin (sandboxed iframes / redirects / local files). "
            "A page in a null-origin context can make cross-origin reads. Review."))
    return findings


# --------------------------------------------------- verb / method tampering ----
_SAFE_METHODS = ["OPTIONS", "HEAD"]
_CASE_VARIANTS = ["Get", "GET ", "get"]   # verb-tampering auth-bypass (filter often matches exact "GET")
_WRITE_METHODS = ["POST", "PUT", "PATCH", "DELETE"]


def run_verb_tampering(session, base: str, urls: list[str], *,
                       delay: float = 0.2, timeout: float = 12.0, max_endpoints: int = 120,
                       throttle=None) -> list[dict]:
    """Detect method/verb-based broken access control (BFLA). SAFE default: for endpoints that are
    protected (401/403 unauth), retry unauthenticated with HEAD and method-case variants — if any
    returns data, the auth filter is method-specific (classic verb-tampering bypass). Also enumerate
    server-advertised methods via OPTIONS. Write-method probing only under D4ST_METHOD_TAMPER_WRITES=1."""
    import httpx

    from .safety import pace

    origin = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"
    api = [u for u in urls if u.startswith(origin) and "/api/" in u.lower()][:max_endpoints]
    if not api:
        return []
    authed = _authed_headers(session, base)
    noauth = {k: v for k, v in authed.items() if k.lower() not in ("authorization", "cookie")}
    do_writes = os.environ.get("D4ST_METHOD_TAMPER_WRITES") == "1"
    findings: list[dict] = []
    seen: set[str] = set()

    with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as c:
        for u in api:
            if u in seen:
                continue
            seen.add(u)
            # baseline: authed GET (oracle) + unauth GET (is it protected?)
            try:
                a = c.get(u, headers=authed); pace(throttle, delay, a.status_code)
                n = c.request("GET", u, headers=noauth); pace(throttle, delay, n.status_code)
            except Exception:  # noqa: BLE001
                continue
            if a.status_code >= 400:
                continue
            protected = n.status_code in (401, 403)

            # 1) verb-tampering auth bypass (SAFE — HEAD + GET-case only, unauthenticated)
            if protected:
                for meth in _SAFE_METHODS + _CASE_VARIANTS:
                    try:
                        rr = c.request(meth.strip() or "GET", u, headers=noauth)
                        pace(throttle, delay, rr.status_code)
                    except Exception:  # noqa: BLE001
                        continue
                    # a protected GET (401/403) that answers <400 to a different method/case = bypass
                    if rr.status_code < 400 and rr.status_code != n.status_code:
                        findings.append({
                            "type": "verb-tampering-auth-bypass", "name": "verb-tampering-auth-bypass",
                            "severity": "high", "url": u, "method": meth.strip() or "GET",
                            "category": "broken-access-control", "verified": True,
                            "detail": f"endpoint returns {n.status_code} to an unauthenticated GET but "
                                      f"{rr.status_code} to an unauthenticated '{meth.strip() or 'GET'}' "
                                      f"request — the authorization filter is method-specific and can be "
                                      f"bypassed by altering the HTTP method/case.",
                            "evidence_log": [
                                exchange("Unauthenticated GET (correctly rejected)", n),
                                exchange(f"Unauthenticated '{meth.strip() or 'GET'}' (BYPASS — accepted)", rr)],
                            "repro": curl(rr),
                        })
                        break

            # 2) advertised-method enumeration (informational, safe)
            try:
                opt = c.request("OPTIONS", u, headers=authed); pace(throttle, delay, opt.status_code)
                allow = opt.headers.get("allow") or opt.headers.get("access-control-allow-methods") or ""
            except Exception:  # noqa: BLE001
                allow = ""
            if allow and any(m in allow.upper() for m in _WRITE_METHODS):
                findings.append({
                    "type": "http-methods-advertised", "name": "http-methods-advertised",
                    "severity": "info", "url": u, "method": "OPTIONS",
                    "category": "misconfiguration", "verified": True,
                    "detail": f"OPTIONS advertises state-changing methods on this data endpoint: "
                              f"Allow/ACAM = '{allow}'. Confirm each is authorization-gated.",
                    "evidence_log": [exchange("OPTIONS — advertised methods", opt)],
                    "repro": curl(opt),
                })

            # 3) OPT-IN write-method BFLA (never mutates unless the operator explicitly enables it)
            if do_writes:
                for meth in _WRITE_METHODS:
                    try:
                        wr = c.request(meth, u, headers=authed); pace(throttle, delay, wr.status_code)
                    except Exception:  # noqa: BLE001
                        continue
                    if wr.status_code < 400:
                        findings.append({
                            "type": "bfla-write-method", "name": "bfla-write-method",
                            "severity": "high", "url": u, "method": meth,
                            "category": "broken-access-control", "verified": True,
                            "detail": f"{meth} on a read endpoint returned {wr.status_code} (not "
                                      f"405/403) — the function-level access control may permit "
                                      f"state-changing operations. (D4ST_METHOD_TAMPER_WRITES=1)",
                            "evidence_log": [exchange(f"{meth} request (authed)", wr)],
                            "repro": curl(wr),
                        })
                        break
    return findings


# ---------------------------------------------------- secret live-validation ----
_KEY_KINDS = [
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{20,}")),
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("stripe-key", re.compile(r"sk_(live|test)_[0-9A-Za-z]{16,}")),
    ("slack-token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
]


def assess_secrets(findings: list, *, delay: float = 0.3, timeout: float = 10.0) -> list[dict]:
    """For disclosed keys already found (JS/secret findings), add a scoped IMPACT assessment. Static
    by default; D4ST_SECRET_VALIDATE=1 does a live restriction check (calls the vendor API with the
    client's OWN key — off by default because it egresses to a third party)."""
    live = os.environ.get("D4ST_SECRET_VALIDATE") == "1"
    out: list[dict] = []
    seen: set[str] = set()
    for f in findings or []:
        blob = " ".join(str(getattr(f, x, "") or "") for x in ("evidence", "payload", "raw_output")) \
            if not isinstance(f, dict) else " ".join(str(f.get(x, "") or "") for x in ("detail", "evidence", "payload"))
        for kind, rx in _KEY_KINDS:
            m = rx.search(blob)
            if not m:
                continue
            key = m.group(0)
            if key in seen:
                continue
            seen.add(key)
            url = getattr(f, "url", "") if not isinstance(f, dict) else f.get("url", "")
            if kind == "google-api-key":
                out.append(_assess_google(key, url, live, delay, timeout))
            else:
                out.append({
                    "type": "secret-impact", "name": "secret-impact", "severity": "high",
                    "url": url, "method": "GET", "category": "secret-disclosure", "verified": False,
                    "detail": f"disclosed {kind} '{key[:6]}…{key[-4:]}'. Assess scope/permissions and "
                              f"rotate. (Automated live validation supported for google-api-key; "
                              f"others flagged for manual scope review.)",
                    "evidence_log": [synthetic_exchange(f"disclosed {kind}", method="GET", url=url,
                                                         resp_body=f"{kind}: {key[:6]}…{key[-4:]}")],
                    "repro": "# rotate this credential; verify least-privilege scoping",
                })
    return out


def _assess_google(key: str, url: str, live: bool, delay: float, timeout: float) -> dict:
    masked = f"{key[:8]}…{key[-4:]}"
    if not live:
        return {
            "type": "secret-impact", "name": "secret-impact", "severity": "medium",
            "url": url, "method": "GET", "category": "secret-disclosure", "verified": False,
            "detail": f"disclosed Google API key {masked}. Impact depends on API + HTTP-referrer/IP "
                      f"restrictions: an UNrestricted Maps/Geocoding key allows billable API abuse "
                      f"against the client's account. Set D4ST_SECRET_VALIDATE=1 to live-check "
                      f"restrictions, or verify in the Google Cloud console that the key is referrer/"
                      f"API-restricted. Rotate regardless (it is public in the JS bundle).",
            "evidence_log": [synthetic_exchange("disclosed Google API key (static assessment)",
                                                method="GET", url=url, resp_body=f"key: {masked}")],
            "repro": "# GCP console → APIs & Services → Credentials → restrict + rotate the key",
        }
    import httpx
    probe = ("https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre&key=" + key)
    try:
        with httpx.Client(verify=False, timeout=timeout) as c:
            r = c.get(probe); time.sleep(delay)
        body = r.text or ""
        status = ""
        try:
            status = (r.json() or {}).get("status", "")
        except Exception:  # noqa: BLE001
            pass
        unrestricted = status == "OK"
        sev = "high" if unrestricted else "low"
        verdict = ("UNRESTRICTED — the key answered a live Geocoding request; it is usable for "
                   "billable API abuse against the client's Google account.") if unrestricted else \
                  (f"restricted/limited (Geocoding status: {status or 'denied'}) — lower risk, but "
                   f"still rotate as it is publicly disclosed.")
        return {
            "type": "secret-impact", "name": "secret-impact", "severity": sev,
            "url": url, "method": "GET", "category": "secret-disclosure", "verified": unrestricted,
            "detail": f"disclosed Google API key {masked}: {verdict}",
            "evidence_log": [synthetic_exchange("live restriction check (Geocoding API)", method="GET",
                                                url=probe.replace(key, masked), status=r.status_code,
                                                resp_body=body[:800])],
            "repro": f"curl -s 'https://maps.googleapis.com/maps/api/geocode/json?address=test&key={masked}'",
        }
    except Exception as e:  # noqa: BLE001
        return {
            "type": "secret-impact", "name": "secret-impact", "severity": "medium",
            "url": url, "method": "GET", "category": "secret-disclosure", "verified": False,
            "detail": f"disclosed Google API key {masked}; live check failed ({e}). Rotate + restrict.",
            "evidence_log": [synthetic_exchange("disclosed Google API key", method="GET", url=url,
                                                resp_body=f"key: {masked}")],
            "repro": "# rotate + restrict in GCP console",
        }
