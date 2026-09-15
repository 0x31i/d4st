"""Form-security checks — the login/HTML-form surface a Burp passive scan analyses.

Three checks a header/hygiene scanner misses, high value on any login-gated app (where the form
IS the unauthenticated attack surface):
  1. cleartext credential submission — a password field posted over http:// (or to an http action)
  2. missing CSRF token          — a state-changing (POST) form with no anti-CSRF token field
  3. input reflection            — a submitted marker echoed unencoded in the response (XSS precursor)

(1) and (2) are passive (parse the already-fetched HTML). (3) sends ONE benign canary per form and
checks whether it reflects — a single request, no brute force, honours the caller's cookie.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

_CSRF_HINTS = ("csrf", "token", "nonce", "authenticity", "__requestverification", "xsrf", "_token")
_TEXTY = {"text", "search", "email", "url", "tel", "", "textarea"}


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"method": a.get("method", "get").lower(), "action": a.get("action", ""),
                         "fields": []}
            self.forms.append(self._cur)
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            self._cur["fields"].append((a.get("name", ""), a.get("type", "").lower() if tag == "input" else tag))

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def _parse_forms(html: str) -> list[dict]:
    p = _FormParser()
    try:
        p.feed(html or "")
    except Exception:  # noqa: BLE001 - malformed HTML must not sink the scan
        pass
    return p.forms


def analyze_forms(url: str, body: str) -> list[dict]:
    """Passive checks (1) + (2) over the page's forms."""
    out: list[dict] = []
    page_http = urlsplit(url).scheme == "http"
    for f in _parse_forms(body):
        types = {t for _, t in f["fields"]}
        names = {n.lower() for n, _ in f["fields"] if n}
        has_pw = "password" in types
        action = f["action"] or url
        action_http = action.startswith("http://") or (not action.startswith("http") and page_http)
        # (1) cleartext credential submission
        if has_pw and action_http:
            out.append(dict(
                check="cleartext-credential-submission", category="cleartext-credential-submission",
                url=url, severity="high",
                detail=f"A password field is submitted over cleartext HTTP (form action: "
                       f"{action or '(self)'}). Credentials are exposed to any network observer."))
        # (2) missing CSRF token on a state-changing form
        meaningful = [n for n, t in f["fields"] if n and t not in ("submit", "button", "image", "reset")]
        has_csrf = any(any(h in n for h in _CSRF_HINTS) for n in names)
        if f["method"] == "post" and meaningful and not has_csrf:
            out.append(dict(
                check="csrf-token-missing", category="csrf", url=url, severity="medium",
                detail=f"A state-changing POST form has no anti-CSRF token field "
                       f"(fields: {', '.join(meaningful[:6])}). Requests may be forgeable cross-site."))
    return out


def probe_reflection(url: str, body: str, cookie: str = "", *, timeout: float = 10.0,
                     submit_password_forms: bool = True) -> list[dict]:
    """Check (3): submit a single unique canary per form and report if it reflects UNENCODED
    (an XSS precursor). One request per form. Password forms are probed too (a single failed login),
    which is what surfaces reflected error messages; set submit_password_forms=False to skip them."""
    import httpx

    out: list[dict] = []
    canary = "d4stRX9z1q"          # distinctive, harmless marker
    hdrs = {"Cookie": cookie} if cookie else {}
    forms = _parse_forms(body)
    with httpx.Client(verify=False, follow_redirects=True, timeout=timeout) as c:
        for f in forms:
            fields = [(n, t) for n, t in f["fields"] if n]
            if not fields:
                continue
            if any(t == "password" for _, t in fields) and not submit_password_forms:
                continue
            data = {n: (canary if t in _TEXTY or t == "password" else "1") for n, t in fields}
            action = urljoin(url, f["action"] or "")
            try:
                if f["method"] == "post":
                    r = c.post(action, data=data, headers=hdrs)
                else:
                    r = c.get(action, params=data, headers=hdrs)
            except Exception:  # noqa: BLE001
                continue
            rt = r.text or ""
            # reflected unencoded (the raw canary, not an entity-escaped copy) => XSS precursor
            if canary in rt:
                refl_field = next((n for n, t in fields if t in _TEXTY or t == "password"), fields[0][0])
                proof = [{
                    "label": "PROOF — submitted marker reflected unencoded",
                    "request": {"method": f["method"].upper(), "url": action,
                                "headers": {"Cookie": "<redacted>"} if cookie else {},
                                "body": "&".join(f"{k}={v}" for k, v in data.items())[:400]},
                    "response": {"status": r.status_code, "headers": dict(r.headers),
                                 "body": rt[:6000]},
                }]
                out.append(dict(
                    check="reflected-input", category="reflected-input", url=action, param=refl_field,
                    severity="low",
                    detail=f"Input submitted in '{refl_field}' is reflected unencoded in the response "
                           f"(marker '{canary}' echoed). Reflection point — test for XSS.",
                    evidence_log=proof, repro=f"curl -i -X {f['method'].upper()} '{action}'"))
    return out
