"""Shared evidence helpers — the ONE proof shape every active test emits.

NGS mandate: every finding ships a full request/response block + a copy-paste repro. These helpers
turn an httpx Response into the exact `evidence_log` exchange dict the report/export already render,
so JWT/CORS/method-tamper/WS/authz all produce identical Burp-grade proof with no per-module drift.

Auth secrets are shown as present-but-redacted by default (proof that a bearer WAS/WASN'T sent, which
is the whole point of an authz proof) — D4ST_FULL_AUTH=1 reveals the full token for true Burp parity
when opsec allows.
"""

from __future__ import annotations

import os
import re

_MAX_BODY = 8000

# PHI / regulated-data redaction. When a target handles personal or health data, response bodies
# captured as proof can contain SSNs, DOBs, names, contact and insurance identifiers. Scrub those
# before any body string is persisted to an artifact. Set D4ST_NO_PHI_REDACT=1 to disable (do not
# disable against regulated-data targets).
_PHI_KEYS = re.compile(
    r'(?i)("(?:first_?name|last_?name|middle_?name|full_?name|patient_?name|patientname|dob|'
    r'date_?of_?birth|birth_?date|ssn|social|mrn|medical_?record|member_?id|subscriber|guarantor|'
    r'address\d?|street|city|state|zip|postal|phone|mobile|home_?phone|cell|fax|email|insurance|'
    r'policy_?number|account_?number|chart_?number|dependent)"\s*:\s*)"[^"]*"')
_PHI_SSN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
_PHI_PHONE = re.compile(r'\b(?:\(\d{3}\)\s*|\d{3}[-.\s])\d{3}[-.\s]\d{4}\b')
_PHI_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
_PHI_DOB = re.compile(r'\b\d{1,2}[-/]\d{1,2}[-/](?:19|20)\d{2}\b|\b(?:19|20)\d{2}[-/]\d{1,2}[-/]\d{1,2}\b')
_PHI_LONGNUM = re.compile(r'\b\d{7,}\b')


def _redact_phi(s):
    """Scrub PHI / regulated-data from a body string BEFORE it is persisted to any artifact."""
    if not s:
        return s
    if os.environ.get("D4ST_NO_PHI_REDACT") == "1":
        return s
    try:
        t = s if isinstance(s, str) else str(s)
    except Exception:  # noqa: BLE001
        return s
    t = _PHI_KEYS.sub(lambda m: m.group(1) + '"<PHI-REDACTED>"', t)
    t = _PHI_SSN.sub("<SSN-REDACTED>", t)
    t = _PHI_PHONE.sub("<PHONE-REDACTED>", t)
    t = _PHI_EMAIL.sub("<EMAIL-REDACTED>", t)
    t = _PHI_DOB.sub("<DOB-REDACTED>", t)
    t = _PHI_LONGNUM.sub("<NUM-REDACTED>", t)
    return t


def _full_auth() -> bool:
    return os.environ.get("D4ST_FULL_AUTH") == "1"


def redact_headers(h: dict) -> dict:
    """Show auth presence without leaking the secret (unless D4ST_FULL_AUTH=1)."""
    out = {}
    full = _full_auth()
    for k, v in (h or {}).items():
        lk = k.lower()
        if lk == "authorization" and not full:
            out[k] = (str(v)[:26] + "…<redacted - D4ST_FULL_AUTH=1 to reveal>") if v else v
        elif lk == "cookie" and not full:
            out[k] = "<redacted - D4ST_FULL_AUTH=1 to reveal>"
        else:
            out[k] = v
    return out


def exchange(label: str, r, *, req_body: str = "") -> dict:
    """Build a full labeled request/response exchange from an httpx Response."""
    req = getattr(r, "request", None)
    try:
        elapsed = int(r.elapsed.total_seconds() * 1000)
    except Exception:  # noqa: BLE001
        elapsed = None
    # httpx exposes the sent request body on req.content
    body = req_body
    if not body and req is not None:
        try:
            body = _redact_phi((getattr(req, "content", b"") or b"").decode("utf-8", "replace")[:_MAX_BODY])
        except Exception:  # noqa: BLE001
            body = ""
    return {
        "label": label,
        "request": {
            "method": getattr(req, "method", "GET"),
            "url": str(getattr(req, "url", "")),
            "headers": redact_headers(dict(getattr(req, "headers", {}) or {})),
            "body": _redact_phi(body),
        },
        "response": {
            "status": getattr(r, "status_code", None),
            "headers": dict(getattr(r, "headers", {}) or {}),
            "elapsed_ms": elapsed,
            "size": len(getattr(r, "content", b"") or b""),
            "body": _redact_phi((getattr(r, "text", "") or "")[:_MAX_BODY]),
        },
    }


def curl(r, *, body: str = "") -> str:
    """A copy-paste curl reproducing the request (the one that proves the finding)."""
    req = getattr(r, "request", None)
    if req is None:
        return ""
    parts = [f"curl -i -sk -X {req.method}"]
    skip = {"host", "content-length", "connection", "accept-encoding"}
    full = _full_auth()
    for k, v in (dict(req.headers) or {}).items():
        if k.lower() in skip:
            continue
        if k.lower() == "authorization" and not full:
            v = str(v)[:26] + "…"
        parts.append(f"-H '{k}: {v}'")
    if body:
        parts.append(f"--data '{body[:2000]}'")
    parts.append(f"'{req.url}'")
    return " ".join(parts)


def raw_request(method: str, url: str, headers: dict, body: str = "") -> str:
    """Render a request as the raw HTTP/1.1 text an analyst pastes into Repeater. The one public
    builder (promoted out of the engagement runner) so replay/sweep and the scan pipeline emit
    identical raw proof. Headers are shown as given — redact with redact_headers() first if needed."""
    from urllib.parse import urlsplit
    p = urlsplit(url)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    out = [f"{method} {path} HTTP/1.1", f"Host: {p.netloc}"]
    for k, v in (headers or {}).items():
        if k.lower() == "host":
            continue
        out.append(f"{k}: {v}")
    return "\r\n".join(out) + "\r\n\r\n" + (body or "")


def raw_response(r) -> str:
    """Render an httpx Response as raw HTTP/1.1 text (status line + headers + body)."""
    out = [f"HTTP/1.1 {getattr(r, 'status_code', '')} "
           f"{getattr(r, 'reason_phrase', '') or ''}".rstrip()]
    for k, v in (getattr(r, "headers", {}) or {}).items():
        out.append(f"{k}: {v}")
    return "\r\n".join(out) + "\r\n\r\n" + _redact_phi(getattr(r, "text", "") or "")


def synthetic_exchange(label: str, *, method: str, url: str, req_headers: dict | None = None,
                       req_body: str = "", status=None, resp_headers: dict | None = None,
                       resp_body: str = "") -> dict:
    """An exchange assembled by hand (for tests that don't go through httpx, e.g. a decoded
    token comparison). Same shape so the report renders it identically."""
    return {
        "label": label,
        "request": {"method": method, "url": url,
                    "headers": redact_headers(req_headers or {}),
                    "body": _redact_phi((req_body or "")[:_MAX_BODY])},
        "response": {"status": status, "headers": resp_headers or {},
                     "body": _redact_phi((resp_body or "")[:_MAX_BODY])},
    }
