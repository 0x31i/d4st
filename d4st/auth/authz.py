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
