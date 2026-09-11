"""Authenticated authorization testing — OWASP API1 (BOLA) / API5 (BFLA) / broken auth.

For a token-auth API the highest-value active test isn't payload injection, it's: does the server
actually ENFORCE authorization? This replays each read-only (GET) endpoint the harvest found under
tampered identities and diffs the outcome against the authenticated baseline:

  - no-auth   : strip the bearer entirely  -> expect 401/403; a 200 with real data = BROKEN AUTH
  - bad-token : send a structurally-valid but bogus JWT -> expect reject; 200 = BROKEN TOKEN VALIDATION
  - id-tamper : mutate a numeric id in the query/path -> 200 w/ different valid data = IDOR-SUSPECT

SAFE BY DESIGN: GET endpoints only (no writes/mutation of patient data), throttled (a small delay
between requests, no bursts), and the whole pass is capped. Read-only; it will not DoS the target.
BFLA (function-level) confirmation needs a second, lower-privileged account — noted as a limitation
rather than guessed at from a single session.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from .session import Session

# a structurally-valid JWT with a bogus signature/claims — tests signature/expiry validation
_BOGUS_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJuYW1laWQiOiIwIiwidW5pcXVlX25hbWUiOiJkNHN0LWF1dGh6LXByb2JlIiwiZXhwIjo5OTk5OTk5OTk5fQ."
    "ZDRzdF9pbnZhbGlkX3NpZ25hdHVyZV9ub3RfYWNjZXB0ZWQ"
)
_ID_IN_QUERY = re.compile(r"(^|[?&])([A-Za-z0-9_]*(?:id|Id|ID)[A-Za-z0-9_]*)=(\d+)")


def _auth_header_name(session: Session) -> str:
    for k in session.headers:
        if k.lower() == "authorization":
            return k
    return "Authorization"


def _similar(a: str, b: str) -> bool:
    """Cheap 'looks like the same kind of real response' check by length proximity."""
    la, lb = len(a or ""), len(b or "")
    if la == 0 and lb == 0:
        return True
    hi = max(la, lb) or 1
    return abs(la - lb) / hi < 0.25


def run_authz(session: Session, base: str, urls: list[str], *,
              delay: float = 0.15, timeout: float = 12.0, max_endpoints: int = 300) -> list[dict]:
    """Return a list of authorization findings (dicts). Read-only; throttled by `delay`."""
    import httpx

    origin = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"
    api = [u for u in urls if u.startswith(origin) and "/api/" in u.lower()][:max_endpoints]
    if not api:
        return []

    hname = _auth_header_name(session)
    authed = dict(session.headers)
    cookie = session.cookie_header(base)
    if cookie:
        authed["Cookie"] = cookie
    noauth = {k: v for k, v in authed.items() if k.lower() not in ("authorization", "cookie")}
    badtok = dict(noauth); badtok[hname] = f"Bearer {_BOGUS_JWT}"

    findings: list[dict] = []
    seen: set[str] = set()
    with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as c:
        for url in api:
            if url in seen:
                continue
            seen.add(url)
            try:
                base_r = c.get(url, headers=authed)
            except Exception:
                continue
            time.sleep(delay)
            # only reason about endpoints that actually serve data when authed
            if base_r.status_code >= 400:
                continue
            b_body = base_r.text

            # 1) no-auth: should be rejected
            try:
                na = c.get(url, headers=noauth)
                time.sleep(delay)
                if na.status_code < 400 and _similar(na.text, b_body):
                    findings.append(_f("broken-auth", "critical", url,
                                       f"endpoint returns {na.status_code} with data when the bearer "
                                       f"is removed (authed baseline {base_r.status_code})", base_r, na))
                    continue  # already broken; skip further checks on this one
            except Exception:
                pass

            # 2) bad-token: signature/expiry must be validated
            try:
                bt = c.get(url, headers=badtok)
                time.sleep(delay)
                if bt.status_code < 400 and _similar(bt.text, b_body):
                    findings.append(_f("broken-token-validation", "high", url,
                                       f"endpoint returns {bt.status_code} with data for a bogus/"
                                       f"invalid JWT (baseline {base_r.status_code})", base_r, bt))
            except Exception:
                pass

            # 3) id-tamper (IDOR-suspect): change a numeric id in the query, read-only
            m = _ID_IN_QUERY.search(url)
            if m:
                tampered = _tamper_id(url, m.group(2), m.group(3))
                if tampered and tampered != url:
                    try:
                        it = c.get(tampered, headers=authed)
                        time.sleep(delay)
                        if it.status_code < 400 and len(it.text) > 0 and not _similar(it.text, b_body):
                            findings.append(_f("idor-suspect", "high", tampered,
                                               f"changing {m.group(2)} from {m.group(3)} returned a "
                                               f"different {it.status_code} object — verify it isn't "
                                               f"another tenant's data (manual confirm)", base_r, it))
                    except Exception:
                        pass
    return findings


def _tamper_id(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query))
    try:
        q[param] = str(int(value) + 1)
    except ValueError:
        return ""
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _f(kind: str, severity: str, url: str, detail: str, base_r, probe_r) -> dict:
    return {
        "type": kind, "name": kind, "severity": severity, "url": url, "method": "GET",
        "detail": detail, "category": "authorization", "verified": True,
        "evidence": {
            "authed_status": getattr(base_r, "status_code", None),
            "probe_status": getattr(probe_r, "status_code", None),
            "probe_snippet": (getattr(probe_r, "text", "") or "")[:400],
        },
    }
