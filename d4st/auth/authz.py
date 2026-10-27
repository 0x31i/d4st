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
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from .session import Session

# a structurally-valid JWT with a bogus signature/claims — tests signature/expiry validation
_BOGUS_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJuYW1laWQiOiIwIiwidW5pcXVlX25hbWUiOiJkNHN0LWF1dGh6LXByb2JlIiwiZXhwIjo5OTk5OTk5OTk5fQ."
    "ZDRzdF9pbnZhbGlkX3NpZ25hdHVyZV9ub3RfYWNjZXB0ZWQ"
)
_ID_IN_QUERY = re.compile(r"(^|[?&])([A-Za-z0-9_]*(?:id|Id|ID)[A-Za-z0-9_]*)=(\d+)")

# Sensitivity markers used to RANK (never suppress) unauth-reachable endpoints, so an analyst sees
# which "returns data without auth" hits actually leak sensitive data vs a by-design-public banner.
_SENS_MARKERS = [
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("api-key", re.compile(r"AIza[0-9A-Za-z_\-]{10,}|AKIA[0-9A-Z]{12,}|sk_[A-Za-z0-9]{10,}")),
    ("jwt/token", re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}|\btoken\"?\s*[:=]")),
    ("connection-string", re.compile(r"(?i)(connectionstring|data source=|initial catalog=|password=)")),
    ("azure-acs-id", re.compile(r"8:acs:[0-9a-f\-]+")),
    ("person-name", re.compile(r"(?i)\b(dr\.?|mr\.?|mrs\.?|ms\.?)\s+[A-Z][a-z]+|\"(userName|providerName|patientName|fullName)\"")),
    ("ssn/dob", re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\"(dob|dateOfBirth|ssn)\"")),
]


def _sensitivity(body: str) -> tuple[int, str]:
    """Rank an unauth response by how sensitive its data is. Returns (rank, label). rank: 2=sensitive
    markers present, 1=has non-trivial data, 0=empty/trivial (likely a by-design-public endpoint)."""
    b = (body or "").strip()
    if not b or b in ("[]", "[[]]", "{}", "null", '""'):
        return 0, "empty/trivial response (likely intentionally public)"
    hits = [name for name, rx in _SENS_MARKERS if rx.search(b)]
    if hits:
        return 2, "SENSITIVE DATA EXPOSED: " + ", ".join(sorted(set(hits)))
    return 1, "non-empty data (no obvious sensitive markers — review)"


# Header names that carry auth material — so the no-auth test actually strips the right one on
# custom-header APIs (e.g. X-App-Token), not only standard Authorization/Cookie.
_AUTH_HDR_RE = re.compile(
    r"(?i)^(authorization|x-[a-z0-9-]*(auth|token)[a-z0-9-]*|[a-z0-9-]*-authentication-token"
    r"|x-api-key|api-key|apikey|x-auth-token|x-access-token)$")


def _auth_header_name(session: Session) -> str:
    for k in session.headers:
        if k.lower() == "authorization":
            return k
    for k in session.headers:                 # custom auth header (bearer-in-a-custom-header APIs)
        if _AUTH_HDR_RE.match(k):
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
              delay: float = 0.15, timeout: float = 12.0, max_endpoints: int = 300,
              throttle=None) -> list[dict]:
    """Return a list of authorization findings (dicts). Read-only; throttled by `delay`."""
    import httpx

    from ..safety import pace

    origin = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"
    api = [u for u in urls if u.startswith(origin) and "/api/" in u.lower()][:max_endpoints]
    if not api:
        return []

    hname = _auth_header_name(session)
    authed = dict(session.headers)
    cookie = session.cookie_header(base)
    if cookie:
        authed["Cookie"] = cookie
    # Strip EVERY auth-bearing header (standard + the detected custom one) so "no-auth" is truly
    # unauthenticated — otherwise a custom-header API would still receive the real token.
    _strip = {"authorization", "cookie", hname.lower()}
    noauth = {k: v for k, v in authed.items() if k.lower() not in _strip}
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
            pace(throttle, delay, base_r.status_code)
            # only reason about endpoints that actually serve data when authed
            if base_r.status_code >= 400:
                continue
            b_body = base_r.text

            # 1) no-auth: should be rejected
            try:
                na = c.get(url, headers=noauth)
                pace(throttle, delay, na.status_code)
                if na.status_code < 400 and _similar(na.text, b_body):
                    _rank, _label = _sensitivity(na.text)
                    findings.append(_f("broken-auth", "critical", url,
                                       f"endpoint returns {na.status_code} with data when the bearer "
                                       f"is removed (authed baseline {base_r.status_code}) | {_label}",
                                       base_r, na, sensitivity=_rank))
                    continue  # already broken; skip further checks on this one
            except Exception:
                pass

            # 2) bad-token: signature/expiry must be validated
            try:
                bt = c.get(url, headers=badtok)
                pace(throttle, delay, bt.status_code)
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
                        pace(throttle, delay, it.status_code)
                        if it.status_code < 400 and len(it.text) > 0 and not _similar(it.text, b_body):
                            findings.append(_f("idor-suspect", "high", tampered,
                                               f"changing {m.group(2)} from {m.group(3)} returned a "
                                               f"different {it.status_code} object — verify it isn't "
                                               f"another tenant's data (manual confirm)", base_r, it))
                    except Exception:
                        pass
    return findings


def replay_once(session, method: str, url: str, *, body: str = "", base: str = "",
                timeout: float = 12.0, verify: bool = False, policy=None, client=None):
    """Send ONE request under `session`'s identity and return the httpx.Response — the atomic unit
    the authz matrix / N-way diff are built from. Method and body are generic (any verb). Identity is
    the session's own headers + cookie_header(base or url). An optional `client` reuses a caller's
    httpx.Client (connection reuse in a loop); otherwise a one-shot client is used. `policy`, if
    given, is called policy(method, url) before the request so an outside driver can add a check."""
    import httpx

    m = (method or "GET").upper()
    if policy is not None:
        policy(m, url)
    hdr = dict(getattr(session, "headers", {}) or {})
    try:
        ck = session.cookie_header(base or url)
        if ck:
            hdr["Cookie"] = ck
    except Exception:  # noqa: BLE001
        pass
    content = body.encode("utf-8") if isinstance(body, str) and body else (body or None)
    if client is not None:
        return client.request(m, url, headers=hdr, content=content)
    with httpx.Client(verify=verify, follow_redirects=False, timeout=timeout) as c:
        return c.request(m, url, headers=hdr, content=content)


def diff_identities(method: str, url: str, sessions: dict, *, body: str = "",
                    owner: str | None = None, base: str = "", delay: float = 0.2,
                    timeout: float = 12.0, verify: bool = False, throttle=None,
                    allow_state_changing: bool = False, policy=None) -> dict:
    """Replay ONE request across many named identities and diff the outcomes — the clean, N-way,
    method-generic access-control check `run_authz_matrix` cannot express (it is 2-account + GET-only
    + `/api/`-filtered). For each identity: replay_once -> status + body. The verdict uses the same
    primitives as the matrix — `_similar` (body shape) + `_sensitivity` (data ranking): a non-owner
    identity returning <400 with a body matching the owner's = access NOT enforced (BOLA/BFLA-shaped);
    a non-owner 401/403 (or a non-matching body) = enforced.

    Read-only by default: a write verb or a destructive/auth path raises ValueError unless
    allow_state_changing=True. `policy(method, url)` runs before each identity's request; a policy
    raise ABORTS that one identity distinctly — it is recorded blocked (blocked=True, status=None),
    NOT as a network error (blocked=False, error=<str>) — so a deliberate block is never confused
    with a request failure.

    Returns: {url, method, owner, verdict: 'enforced'|'bypassed'|'mixed'|'n/a',
              per_identity:[{name, status, size, allowed, matches_owner, sensitivity,
                             blocked, error}],
              evidence_log:[exchange per identity]}."""
    import httpx

    from ..safety import is_auth_endpoint, is_state_changing, pace

    m = (method or "GET").upper()
    if not allow_state_changing and (m not in ("GET", "HEAD", "OPTIONS")
                                     or is_state_changing(url) or is_auth_endpoint(url)):
        raise ValueError(f"{m} {url} is not read-only (write verb or destructive/auth path); "
                         "pass allow_state_changing=True to authorize it")

    names = list(sessions)
    if not names:
        return {"url": url, "method": m, "owner": None, "verdict": "n/a",
                "per_identity": [], "evidence_log": []}
    owner = owner if owner in sessions else names[0]
    order = [owner] + [n for n in names if n != owner]

    per_identity: list[dict] = []
    evidence_log: list[dict] = []
    owner_body: str | None = None
    with httpx.Client(verify=verify, follow_redirects=False, timeout=timeout) as c:
        for name in order:
            # A policy raise is a DELIBERATE block of this identity's probe — it must abort this
            # identity distinctly (recorded blocked/skipped), not be swallowed by the broad except
            # below that only means "the request failed on the network". Evaluate policy here and
            # pass policy=None into replay_once so it is not run (and caught) twice.
            if policy is not None:
                try:
                    policy(m, url)
                except Exception as exc:  # noqa: BLE001
                    per_identity.append({"name": name, "status": None, "size": 0,
                                         "allowed": False, "matches_owner": False,
                                         "sensitivity": 0, "blocked": True, "error": None,
                                         "note": f"policy blocked: {exc}"})
                    continue
            try:
                r = replay_once(sessions[name], m, url, body=body, base=base,
                                policy=None, client=c)
            except Exception as exc:  # noqa: BLE001
                per_identity.append({"name": name, "status": None, "size": 0, "allowed": False,
                                     "matches_owner": False, "sensitivity": 0,
                                     "blocked": False, "error": str(exc)})
                continue
            pace(throttle, delay, r.status_code)
            txt = r.text or ""
            if name == owner:
                owner_body = txt
            rank, label = _sensitivity(txt)
            allowed = r.status_code < 400
            matches = True if name == owner else _similar(txt, owner_body or "")
            per_identity.append({"name": name, "status": r.status_code,
                                 "size": len(r.content or b""), "allowed": allowed,
                                 "matches_owner": matches, "sensitivity": rank,
                                 "sensitivity_label": label, "blocked": False, "error": None})
            evidence_log.append(_exchange(
                f"identity {name!r}" + (" — owner (baseline)" if name == owner else " — PROOF"), r))

    non_owner = [p for p in per_identity if p["name"] != owner]
    bypassed = [p for p in non_owner if p["allowed"] and p["matches_owner"]]
    if not non_owner:
        verdict = "n/a"
    elif len(bypassed) == len(non_owner):
        verdict = "bypassed"
    elif not bypassed:
        verdict = "enforced"
    else:
        verdict = "mixed"
    return {"url": url, "method": m, "owner": owner, "verdict": verdict,
            "per_identity": per_identity, "evidence_log": evidence_log}


def run_authz_matrix(session_a: Session, session_b: Session, base: str, urls: list[str], *,
                     delay: float = 0.2, timeout: float = 12.0, max_endpoints: int = 300,
                     throttle=None) -> list[dict]:
    """TWO-ACCOUNT horizontal access-control test (OWASP API1 BOLA / API5 BFLA) — the definitive
    check a single-session scan structurally cannot do. For each endpoint account A can read, replay
    the SAME request (A's resource ids in the path/query) with account B's token. If B receives A's
    data, one user can read another's records — a real IDOR/BOLA, not a suspicion.

    READ-ONLY: GET only, throttled, capped. Both sessions are the tester's own authorized low-priv
    accounts. The proof is the contrast: A's token -> A's data, B's token -> the SAME data."""
    import httpx

    from ..safety import pace

    origin = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"
    api = [u for u in urls if u.startswith(origin) and "/api/" in u.lower()][:max_endpoints]
    if not api:
        return []

    findings: list[dict] = []
    seen: set[str] = set()
    # Built on the shared atomic unit replay_once: A's request then the SAME request as B. Each
    # session supplies its own identity (headers + cookie_header(base)); GET-only + id-filtered
    # here, exactly as before.
    with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as c:
        for url in api:
            # only endpoints that look object-scoped (carry an id) are BOLA-interesting; endpoints
            # with no id return the caller's OWN collection and would false-positive as "shared".
            has_id = bool(_ID_IN_QUERY.search(url)) or bool(re.search(r"/\d{2,}(?:/|$)", url))
            if url in seen or not has_id:
                continue
            seen.add(url)
            try:
                ra = replay_once(session_a, "GET", url, base=base, client=c)
                pace(throttle, delay, ra.status_code)
            except Exception:  # noqa: BLE001
                continue
            if ra.status_code >= 400 or not (ra.text or "").strip():
                continue
            try:
                rb = replay_once(session_b, "GET", url, base=base, client=c)
                pace(throttle, delay, rb.status_code)
            except Exception:  # noqa: BLE001
                continue
            # B sees A's object: 200 + substantively the same body = horizontal priv-esc (BOLA)
            if rb.status_code < 400 and _similar(rb.text, ra.text) and (rb.text or "").strip():
                _rank, _label = _sensitivity(rb.text)
                findings.append({
                    "type": "bola-cross-account", "name": "bola-cross-account",
                    "severity": "critical", "url": url, "method": "GET",
                    "category": "broken-object-level-authorization", "verified": True,
                    "sensitivity": _rank,
                    "detail": f"account B retrieved account A's object at this endpoint "
                              f"({rb.status_code}, body matches A's) — one authenticated user can read "
                              f"another user's data (horizontal BOLA/IDOR). {_label}",
                    "evidence_log": [
                        _exchange("Account A — owner (A's token) returns A's object", ra),
                        _exchange("PROOF — Account B (different user's token) returns the SAME object", rb)],
                    "repro": _curl(rb),
                    "evidence": {"a_status": ra.status_code, "b_status": rb.status_code,
                                 "b_snippet": (rb.text or "")[:400]},
                })
    return findings


def _tamper_id(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query))
    try:
        q[param] = str(int(value) + 1)
    except ValueError:
        return ""
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


_PROBE_LABEL = {
    "broken-auth": "PROOF — same request with the bearer REMOVED (unauthenticated)",
    "broken-token-validation": "PROOF — same request with a BOGUS/invalid JWT",
    "idor-suspect": "PROOF — same request with a TAMPERED id (authenticated)",
}


def _redact_headers(h: dict) -> dict:
    """Show that auth WAS/WASN'T present (the whole proof) without leaking the full token."""
    out = {}
    for k, v in (h or {}).items():
        lk = k.lower()
        if lk == "authorization":
            out[k] = (str(v)[:26] + "…<redacted>") if v else v
        elif lk == "cookie":
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


def _exchange(label: str, r) -> dict:
    """Build a full labeled request/response exchange from an httpx Response — the evidence."""
    req = getattr(r, "request", None)
    try:
        _elapsed = int(r.elapsed.total_seconds() * 1000)
    except Exception:  # noqa: BLE001
        _elapsed = None
    return {
        "label": label,
        "request": {
            "method": getattr(req, "method", "GET"),
            "url": str(getattr(req, "url", "")),
            "headers": _redact_headers(dict(getattr(req, "headers", {}) or {})),
            "body": "",
        },
        "response": {
            "status": getattr(r, "status_code", None),
            "headers": dict(getattr(r, "headers", {}) or {}),
            "elapsed_ms": _elapsed,
            "size": len(getattr(r, "content", b"") or b""),
            "body": (getattr(r, "text", "") or "")[:8000],
        },
    }


def _curl(r) -> str:
    """A copy-paste curl that reproduces the PROBE request (the one that proves the finding)."""
    req = getattr(r, "request", None)
    if req is None:
        return ""
    parts = [f"curl -i -X {req.method}"]
    _skip = {"host", "content-length", "connection", "accept-encoding"}
    for k, v in (dict(req.headers) or {}).items():
        if k.lower() in _skip:
            continue
        if k.lower() == "authorization":
            v = str(v)[:26] + "…"
        parts.append(f"-H '{k}: {v}'")
    parts.append(f"'{req.url}'")
    return " ".join(parts)


def _f(kind: str, severity: str, url: str, detail: str, base_r, probe_r, sensitivity: int = 1) -> dict:
    # FULL PROOF: the authed baseline exchange (bearer present -> data) AND the tampered probe
    # exchange (bearer removed / bad token / tampered id -> same or different data). The contrast
    # between the two request/response pairs is the evidence an analyst/client needs.
    ev_log = [
        _exchange("Authenticated baseline (valid bearer)", base_r),
        _exchange(_PROBE_LABEL.get(kind, "PROOF — tampered probe"), probe_r),
    ]
    return {
        "type": kind, "name": kind, "severity": severity, "url": url, "method": "GET",
        "detail": detail, "category": "authorization", "verified": True,
        "sensitivity": sensitivity,  # 2=sensitive data, 1=data, 0=empty/likely-public — for ranking
        "evidence_log": ev_log,
        "repro": _curl(probe_r),
        "evidence": {
            "authed_status": getattr(base_r, "status_code", None),
            "probe_status": getattr(probe_r, "status_code", None),
            "probe_snippet": (getattr(probe_r, "text", "") or "")[:400],
        },
    }
