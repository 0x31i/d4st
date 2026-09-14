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

_MAX_BODY = 8000


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
            body = (getattr(req, "content", b"") or b"").decode("utf-8", "replace")[:_MAX_BODY]
        except Exception:  # noqa: BLE001
            body = ""
    return {
        "label": label,
        "request": {
            "method": getattr(req, "method", "GET"),
            "url": str(getattr(req, "url", "")),
            "headers": redact_headers(dict(getattr(req, "headers", {}) or {})),
            "body": body,
        },
        "response": {
            "status": getattr(r, "status_code", None),
            "headers": dict(getattr(r, "headers", {}) or {}),
            "elapsed_ms": elapsed,
            "size": len(getattr(r, "content", b"") or b""),
            "body": (getattr(r, "text", "") or "")[:_MAX_BODY],
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


def synthetic_exchange(label: str, *, method: str, url: str, req_headers: dict | None = None,
                       req_body: str = "", status=None, resp_headers: dict | None = None,
                       resp_body: str = "") -> dict:
    """An exchange assembled by hand (for tests that don't go through httpx, e.g. a decoded
    token comparison). Same shape so the report renders it identically."""
    return {
        "label": label,
        "request": {"method": method, "url": url,
                    "headers": redact_headers(req_headers or {}), "body": (req_body or "")[:_MAX_BODY]},
        "response": {"status": status, "headers": resp_headers or {},
                     "body": (resp_body or "")[:_MAX_BODY]},
    }
