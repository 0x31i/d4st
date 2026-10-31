"""Repeater engine — method-generic one-shot request replay.

`replay()` sends a single fully-specified request and returns the response plus the same
Burp-grade evidence exchange every active test emits (`evidence.exchange`), so a console/report
renders a hand-driven replay identically to a scan finding. This is the clean one-shot d4st's
scan-pipeline capture (`engagement.capture_full_evidence`) is not: it takes an arbitrary request,
honors any verb + body, and merges auth from a captured Session or a raw cookie.

Read-only by default: a write verb or a destructive/auth path is refused unless the caller opts in.
A neutral `policy` hook lets an outside driver add its own pre-request check without this module
knowing anything about it.
"""

from __future__ import annotations

from .evidence import curl, exchange, raw_request, raw_response
from .safety import (browser_headers, is_auth_endpoint, is_session_destroying_endpoint,
                     is_state_changing)

_READ_ONLY_VERBS = {"GET", "HEAD", "OPTIONS"}


def _merge_headers(url: str, headers: dict | None, session, cookie: str) -> dict:
    """Build the outgoing header set: browser defaults, then the session's identity (headers +
    cookie) or a raw cookie string, then the caller's explicit headers on top (they win)."""
    h = browser_headers()
    if session is not None:
        h.update(dict(getattr(session, "headers", {}) or {}))
        try:
            ck = session.cookie_header(url)
            if ck:
                h["Cookie"] = ck
        except Exception:  # noqa: BLE001 - a malformed session must never break a replay
            pass
    if cookie:
        h["Cookie"] = cookie
    if headers:
        h.update(headers)
    return h


def replay(method: str, url: str, *, headers: dict | None = None, body: str | bytes = b"",
           session=None, cookie: str = "", follow_redirects: bool = False,
           timeout: float = 15.0, verify: bool = False, label: str = "replay",
           allow_state_changing: bool = False, policy=None) -> dict:
    """Send one request and return the response fields plus a full evidence exchange.

    - Auth is merged from `session` (auth.session.Session — its headers + cookie_header(url)) or a
      raw `cookie` string; a browser User-Agent is the default.
    - `method` and `body` are honored for ALL verbs (GET/POST/PUT/PATCH/DELETE/...).
    - Read-only by default: a write verb, or a destructive/auth path (safety.is_state_changing /
      safety.is_auth_endpoint), raises ValueError unless allow_state_changing=True.
    - A DELETE verb or a session-destroying endpoint is HARD-REFUSED even with
      allow_state_changing=True (a primitive never auto-fires a deletion / logout).
    - `policy` (optional) is a pluggable pre-request hook called as policy(method, url) BEFORE the
      request is sent; raising from it aborts the replay. d4st attaches no meaning to it — an
      outside driver uses it to add its own checks.

    Returns: {ok, status, elapsed_ms, size, resp_headers, body, exchange, repro,
              raw_request, raw_response}.
    """
    import httpx

    m = (method or "GET").upper()
    if policy is not None:
        policy(m, url)
    # HARD RULE (mirrors engagement.capture_full_evidence): a DELETE verb or a session-destroying
    # (logout) endpoint is NEVER auto-fired by a primitive, even with allow_state_changing=True.
    # Deletion / session teardown stays a deliberate manual action elsewhere.
    if m == "DELETE" or is_session_destroying_endpoint(url):
        raise ValueError(
            f"{m} {url} is refused outright: DELETE / session-destroying requests are never "
            "auto-fired by a primitive; allow_state_changing cannot authorize it")
    if not allow_state_changing and (m not in _READ_ONLY_VERBS
                                     or is_state_changing(url) or is_auth_endpoint(url)):
        raise ValueError(
            f"{m} {url} is not read-only (write verb or destructive/auth path); "
            "pass allow_state_changing=True to authorize it")

    merged = _merge_headers(url, headers, session, cookie)
    body_str = body.decode("utf-8", "replace") if isinstance(body, bytes) else (body or "")
    content = body if isinstance(body, (bytes, bytearray)) else (body.encode("utf-8") if body else None)

    r = httpx.request(m, url, headers=merged, content=content,
                      follow_redirects=follow_redirects, verify=verify, timeout=timeout)

    ex = exchange(label, r, req_body=body_str)
    return {
        "ok": r.status_code < 400,
        "status": r.status_code,
        "elapsed_ms": int(r.elapsed.total_seconds() * 1000) if r.elapsed else None,
        "size": len(r.content or b""),
        "resp_headers": dict(r.headers),
        "body": r.text or "",
        "exchange": ex,
        "repro": curl(r, body=body_str),
        "raw_request": raw_request(m, str(r.request.url),
                                   ex["request"]["headers"], body_str),
        "raw_response": raw_response(r),
    }
