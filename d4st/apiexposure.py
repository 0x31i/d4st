"""Unauthenticated API data-exposure detector (excessive data exposure / BOLA-lite).

A class a header/hygiene scanner misses: an endpoint that, with NO credentials, returns a JSON
body full of other people's records — an array of user/account objects, or an object carrying
credential-shaped fields (password, token, secret, ssn...). On VAmPI this is `/users/v1/_debug`
(every user + plaintext password) and `/users/v1` (the full user list); the generic passive
scanner only saw a low-confidence email and under-rated it.

We GET each candidate endpoint unauthenticated, parse JSON, and rate:
  - credential/secret field present with a real value  -> CRITICAL (unauth credential/secret dump)
  - array of >=2 record objects (bulk data)            -> HIGH     (excessive data exposure)
Schema/spec endpoints (openapi/swagger) are excluded so field *names* in a schema don't false-fire.
Every finding carries the real request/response as proof.
"""

from __future__ import annotations

import json
import os
from urllib.parse import urlsplit

# fields whose PRESENCE-with-a-value in an unauth response is a credential/secret leak
_CRED_KEYS = {
    "password", "passwd", "pwd", "pass", "secret", "token", "apikey", "api_key", "access_token",
    "refresh_token", "id_token", "private_key", "privatekey", "secret_key", "client_secret",
    "sessionid", "session_id", "session_token", "auth_token", "hash", "password_hash", "pwhash",
    "ssn", "social_security", "credit_card", "creditcard", "card_number", "cvv", "pin",
}
# record-ish object hint keys (used to decide an array is a bulk data dump, not e.g. a list of ints)
_RECORD_HINT = {"id", "username", "user", "email", "name", "role", "admin", "account", "first_name",
                "last_name", "phone", "address", "dob", "created", "uuid", "user_id"}


def _is_spec_url(u: str) -> bool:
    lu = u.lower()
    return any(s in lu for s in ("openapi", "swagger", "/api-docs", "/v2/api-docs", ".yaml", ".yml"))


def _walk(obj, depth=0):
    """Yield (key, value) for every dict entry, and mark arrays-of-objects. Bounded depth."""
    if depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield ("__key__", k, v)
            yield from _walk(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v, depth + 1)


def _cred_hits(data) -> list[tuple[str, str]]:
    """(key, short-value) for credential-shaped keys that carry a real scalar value."""
    out = []
    for tag, k, v in _walk(data):
        if tag != "__key__":
            continue
        if str(k).lower().strip("_") in _CRED_KEYS and isinstance(v, (str, int)) and str(v).strip():
            out.append((str(k), str(v)[:40]))
    return out


def _record_arrays(data) -> list[tuple[str, int, list]]:
    """(path-ish label, count, sample-keys) for each array of >=2 record-like objects."""
    found = []

    def rec(node, label):
        if isinstance(node, list):
            objs = [x for x in node if isinstance(x, dict)]
            if len(objs) >= 2 and any(set(map(str.lower, o.keys())) & _RECORD_HINT for o in objs[:3]):
                found.append((label, len(objs), sorted(objs[0].keys())[:8]))
            for i, x in enumerate(node[:3]):
                rec(x, f"{label}[{i}]")
        elif isinstance(node, dict):
            for k, v in node.items():
                rec(v, f"{label}.{k}" if label else str(k))

    rec(data, "")
    return found


def _xml_hits(body: str):
    """Conservative exposure check for XML API bodies. Returns (creds, arrays) in the same shape as
    the JSON path. Flags only clear bulk (>=2 sibling record elements) and credential-named elements
    with a value — so an XML-serialized API can't hide a bulk/credential dump behind its format."""
    import xml.etree.ElementTree as ET

    def _local(t: str) -> str:
        return t.rsplit("}", 1)[-1].lower()

    try:
        root = ET.fromstring(body)
    except Exception:  # noqa: BLE001
        return [], []
    # bulk: >=2 sibling elements that are themselves records (have children or text)
    recs = [c for c in list(root) if len(list(c)) > 0 or (c.text and c.text.strip())]
    arrays = []
    if len(recs) >= 2:
        sample = sorted({_local(x.tag) for c in recs[:3] for x in list(c)})[:8]
        arrays = [("xml-records", len(recs), sample or [_local(recs[0].tag)])]
    # creds: an element whose tag is a credential/secret key and carries a non-empty value
    creds = []
    for el in root.iter():
        if _local(el.tag) in _CRED_KEYS and el.text and el.text.strip():
            creds.append((_local(el.tag), el.text.strip()))
    return creds, arrays


def scan_api_exposure(urls: list[str], cookie: str = "", *, authed: bool = False,
                      cap: int = 120, timeout: float = 10.0) -> list[dict]:
    """GET each candidate URL (unauth unless a cookie is supplied) and flag JSON bodies that leak
    bulk records or credential/secret fields. Returns finding dicts (category/url/severity hint via
    category + evidence_log)."""
    import httpx

    from .safety import browser_headers
    headers = browser_headers({"Cookie": cookie} if cookie else None)
    # Prefer JSON. Content-negotiating APIs (ASP.NET/WebAPI) return XML to a browser Accept header,
    # which hid bulk data from this detector (a content-negotiating API served <ArrayOf...> XML to the default Accept).
    # Ask for JSON explicitly while keeping the browser UA so WAFs don't tarpit us.
    headers["Accept"] = "application/json, text/plain, */*"
    seen: set = set()
    out: list[dict] = []
    # focus on likely-JSON/API endpoints; skip static assets and spec docs
    cand = [u for u in urls if not _is_spec_url(u)
            and not u.split("?")[0].lower().endswith(
                (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
                 ".map", ".pdf"))]
    for url in cand[:cap]:
        key = url.split("?")[0]
        if key in seen:
            continue
        seen.add(key)
        try:
            r = httpx.get(url, headers=headers, follow_redirects=True, verify=False, timeout=timeout)
        except Exception:  # noqa: BLE001
            continue
        ct = r.headers.get("content-type", "").lower()
        body = r.text or ""
        start = body.lstrip()[:1]
        # any 2xx is a successful read — some APIs answer GETs with 202/203/206, not just 200
        # (some APIs return 202). Hardcoding 200 silently skipped the entire API surface.
        if not (200 <= r.status_code < 300):
            continue
        looks_json = ("json" in ct) or start in ("{", "[")
        looks_xml = ("xml" in ct) or start == "<"
        if not (looks_json or looks_xml):
            continue
        creds: list = []
        arrays: list = []
        if looks_json:
            try:
                data = json.loads(body)
                creds = _cred_hits(data)
                arrays = _record_arrays(data)
            except Exception:  # noqa: BLE001
                pass
        # XML fallback — some APIs only speak XML (or content-negotiate to it); the same bulk /
        # credential exposure still applies, so don't let a serialization format hide it.
        if not creds and not arrays and looks_xml:
            creds, arrays = _xml_hits(body)
        if not creds and not arrays:
            continue
        proof = [{
            "label": "PROOF — unauthenticated response body",
            "request": {"method": "GET", "url": str(r.url),
                        "headers": {"Cookie": "<redacted>"} if cookie else {}, "body": ""},
            "response": {"status": r.status_code, "headers": dict(r.headers),
                         "size": len(r.content), "body": body[:8000]},
        }]
        repro = f"curl -i '{url}'"
        who = "with a valid session" if authed else "with NO authentication"
        if creds:
            klist = ", ".join(sorted({k for k, _ in creds}))
            out.append(dict(
                category="unauth-credential-exposure" if not authed else "excessive-data-exposure",
                url=str(r.url), method="GET",
                evidence=f"Endpoint returns credential/secret fields ({klist}) {who} — "
                         f"{len(creds)} sensitive value(s) in the response body.",
                evidence_log=proof, repro=repro, verified=True, tool="api-exposure",
                detection="unauth API data-exposure probe"))
        elif arrays:
            lbl, n, ks = max(arrays, key=lambda a: a[1])
            out.append(dict(
                category="excessive-data-exposure", url=str(r.url), method="GET",
                evidence=f"Endpoint returns {n} record objects {who} (fields: {', '.join(ks)}) — "
                         f"bulk data exposure / missing object-level authorization.",
                evidence_log=proof, repro=repro, verified=True, tool="api-exposure",
                detection="unauth API data-exposure probe"))
    return out
