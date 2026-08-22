"""Form + CSRF-token discovery.

Real engagements are blind: we don't know the injectable points, and every state-changing
form usually carries a per-request anti-CSRF token. This module fetches pages, extracts each
<form> (method, action, fields), and detects the CSRF-token field so the injection tools can
(a) test POST params they'd otherwise miss and (b) get past the CSRF gate on hardened apps.

Pure stdlib (html.parser + urllib) so it has no extra dependency and is unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

# Common anti-CSRF hidden-field names across frameworks.
CSRF_FIELDS = {
    "user_token", "csrf_token", "csrftoken", "csrf", "_csrf", "_token",
    "authenticity_token", "__requestverificationtoken", "csrfmiddlewaretoken",
    "anti_csrf", "xsrf_token", "_csrf_token", "nonce",
}


@dataclass
class FormSpec:
    action: str                       # absolute URL the form submits to
    method: str = "GET"               # GET | POST
    params: list[str] = field(default_factory=list)      # editable field names
    values: dict = field(default_factory=dict)           # default values (name->value)
    csrf_field: str | None = None     # detected anti-CSRF field name, if any
    source_url: str = ""              # page the form was found on

    @property
    def csrf_url(self) -> str:
        # Where a tool should GET a fresh token from: the page the form lives on.
        return self.source_url or self.action

    def injectable_params(self) -> list[str]:
        """Params worth testing (exclude the CSRF token + submit buttons)."""
        skip = {self.csrf_field} if self.csrf_field else set()
        return [p for p in self.params if p and p not in skip]


class _FormParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.forms: list[FormSpec] = []
        self._cur: FormSpec | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            action = urljoin(self.base_url, a.get("action", "") or self.base_url)
            self._cur = FormSpec(action=action, method=(a.get("method", "get") or "get").upper(),
                                 source_url=self.base_url)
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = a.get("name")
            if not name:
                return
            self._cur.params.append(name)
            self._cur.values[name] = a.get("value", "")
            itype = a.get("type", "").lower()
            if name.lower() in CSRF_FIELDS or (itype == "hidden" and "token" in name.lower()):
                self._cur.csrf_field = name

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None

    def close_open(self):
        if self._cur is not None:  # unterminated form
            self.forms.append(self._cur)
            self._cur = None


def extract_forms(html: str, base_url: str) -> list[FormSpec]:
    p = _FormParser(base_url)
    try:
        p.feed(html or "")
    except Exception:  # noqa: BLE001 - malformed HTML must not crash discovery
        pass
    p.close_open()
    return p.forms


def fetch_forms(url: str, cookie: str = "", timeout: float = 12.0) -> list[FormSpec]:
    import httpx
    headers = {"Cookie": cookie} if cookie else {}
    try:
        r = httpx.get(url, headers=headers, follow_redirects=True, timeout=timeout)
    except Exception:  # noqa: BLE001
        return []
    return extract_forms(r.text, str(r.url))


def csrf_for_url(url: str, cookie: str = "") -> tuple[str | None, str]:
    """Best-effort (csrf_field_name, csrf_url) for a target URL: fetch it, take the first
    form that carries a token. Returns (None, url) if no token form is found."""
    for f in fetch_forms(url, cookie):
        if f.csrf_field:
            return f.csrf_field, f.csrf_url
    return None, url


def same_host(url: str, host: str) -> bool:
    # host may include a port (localhost:3000); urlsplit(...).hostname strips it. Compare
    # hostname to hostname so scope checks don't fail on any non-80/443 target.
    want = (host or "").rsplit("@", 1)[-1].split(":")[0].lower()
    return (urlsplit(url).hostname or want).lower() == want
