"""Credential differential probe — "is this account actually provisioned here?"

A read-only, lockout-safe way to answer, with evidence, whether a set of credentials is
provisioned on a login page — and to distinguish *not provisioned* from *wrong password* from
*logged in*. The core trick (and why the verdict is trustworthy rather than a guess): alongside
the real credentials we submit a **deliberately non-existent username** as a baseline. If the
server's response to the real account is byte-identical to its response to an account that
cannot exist, the real account is not in that app's user store. If it differs, the account may
exist (locked / must-reset / distinct error) and is worth a human look. If the login succeeds,
it's provisioned and the password is right.

Two independent lenses, so one corroborates the other:
  - **browser** (Playwright): drives the real login form, running whatever client-side JS the
    page uses (custom onclick handlers, AJAX, SPA token flows), and captures the *real* login
    API call's status+body plus a screenshot. This is the authoritative lens for JS-driven logins.
  - **raw** (httpx): replays the discovered login endpoint directly, no browser. Independent
    corroboration — but only honest when the page does NOT hash the password client-side
    (we detect and warn on that).

Nothing here is a brute-force: it issues at most one attempt per (credential, lens), and a
non-existent account has no lockout counter to trip. Playwright is imported lazily so the raw
lens and the classifier work without browser binaries installed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

# A username that must not exist in any real user store — the differential baseline.
DEFAULT_FAKE_USER = "zz_nouser_probe_9731"

# URL fragments that mark a request as the login/auth call (for network discovery + raw replay).
_AUTH_URL_HINTS = ("login", "authenticate", "authentication", "authuser", "auth",
                   "signin", "validate", "account", "token", "session")

# Client-side password-handling markers — if present, a raw-HTTP replay of a plaintext password
# is unreliable (the browser would transform it first), so we flag the raw lens as untrustworthy.
_CLIENT_HASH_HINTS = re.compile(
    r"(cryptojs|\bmd5\b|sha1|sha256|sha512|\.hash\(|encryptpassword|hashpassword|bcrypt|"
    r"jsencrypt|pidcrypt|\brsa\b)", re.I)

_INVALID_WORDS = ("invalid", "incorrect", "not valid", "failed", "denied",
                  "wrong", "unauthorized", "bad credentials")
# Error phrases that suggest the account EXISTS but this login was refused for another reason —
# these should NOT read as "not provisioned". Word-boundary matched so "blocked" does not hit
# "locked", etc.
_ACCOUNT_EXISTS_RE = re.compile(
    r"\b(locked|disabled|expired|suspended|deactivated|"
    r"must\s+reset|must\s+change|too\s+many\s+attempts)\b", re.I)


class Verdict(str, Enum):
    LOGGED_IN = "LOGGED_IN"                  # provisioned + correct password (positive control)
    NOT_PROVISIONED = "NOT_PROVISIONED"      # identical to the non-existent baseline
    ACCOUNT_EXISTS_REFUSED = "ACCOUNT_EXISTS_REFUSED"  # differs from baseline, not logged in (locked/etc.)
    DISTINCT_REJECTION = "DISTINCT_REJECTION"  # differs from baseline but no exists-marker; investigate
    INDETERMINATE = "INDETERMINATE"


@dataclass
class Attempt:
    """One (credential, lens) outcome."""
    label: str                 # e.g. "FAKE", "alice"
    username: str
    lens: str                  # "browser" | "raw"
    status: int | None = None  # HTTP status of the login API call
    body: str = ""             # login API response body (truncated)
    visible_error: str = ""    # rendered error text (browser lens)
    logged_in: bool = False    # moved off login / success token present / 2xx w/o error
    screenshot: str | None = None
    note: str = ""


@dataclass
class AppProbe:
    target: str
    login_url: str | None = None
    api_endpoint: str | None = None
    api_method: str | None = None
    client_side_hashing: bool = False
    attempts: list[Attempt] = field(default_factory=list)
    verdicts: dict = field(default_factory=dict)   # cred label -> Verdict (browser lens)
    raw_verdicts: dict = field(default_factory=dict)  # cred label -> Verdict (raw lens)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        """JSON-serializable view. Centralizes serialization so callers never hand-build JSON
        (raw login-API response bodies carry newlines/backslashes/markup, so callers MUST emit
        this via json.dumps + a raw writer like click.echo — never Rich console.print, which
        line-wraps and interprets markup, corrupting the JSON)."""
        def _v(d: dict) -> dict:
            return {k: (val.value if isinstance(val, Verdict) else val) for k, val in d.items()}
        return {
            "target": self.target,
            "login_url": self.login_url,
            "api_endpoint": self.api_endpoint,
            "api_method": self.api_method,
            "client_side_hashing": self.client_side_hashing,
            "verdicts": _v(self.verdicts),
            "raw_verdicts": _v(self.raw_verdicts),
            "attempts": [vars(a) for a in self.attempts],
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# Pure classification (unit-testable, no I/O)                                  #
# --------------------------------------------------------------------------- #

def _norm(body: str, n: int = 160) -> str:
    return re.sub(r"\s+", " ", (body or "")).strip().lower()[:n]


def _looks_logged_in(status: int | None, body: str, *, moved: bool,
                     token_present: bool) -> bool:
    if token_present or moved:
        return True
    b = _norm(body)
    if status is not None and 200 <= status < 300 and not any(w in b for w in _INVALID_WORDS):
        return True
    return False


def classify_verdict(real: Attempt, fake: Attempt) -> Verdict:
    """Classify a real-credential attempt against the non-existent-user baseline."""
    if real.logged_in:
        return Verdict.LOGGED_IN
    same_status = real.status == fake.status
    same_body = _norm(real.body) == _norm(fake.body)
    if real.status is None and fake.status is None and not real.body and not fake.body:
        # Neither reached the login API at all — can't conclude.
        return Verdict.INDETERMINATE
    if same_status and same_body:
        return Verdict.NOT_PROVISIONED
    # Differs from the baseline → the account is being treated specially.
    blob = _norm(real.visible_error + " " + real.body, 400)
    if _ACCOUNT_EXISTS_RE.search(blob):
        return Verdict.ACCOUNT_EXISTS_REFUSED
    return Verdict.DISTINCT_REJECTION


# --------------------------------------------------------------------------- #
# Raw (browser-independent) lens                                              #
# --------------------------------------------------------------------------- #

def build_raw_query(endpoint_url: str) -> tuple[str, dict]:
    """Split a discovered GET login URL into (base_endpoint, param_template).

    The template keeps every observed param (so the Web-API route still matches) with the
    username/password values blanked for substitution. Returns ("", {}) if no query."""
    sp = urlsplit(endpoint_url)
    if not sp.query:
        return (f"{sp.scheme}://{sp.netloc}{sp.path}", {})
    params: dict[str, str] = {}
    for pair in sp.query.split("&"):
        if not pair:
            continue
        k, _, v = pair.partition("=")
        params[k] = v
    return (f"{sp.scheme}://{sp.netloc}{sp.path}", params)


def _is_pw_key(k: str) -> bool:
    kl = k.lower()
    return "pass" in kl or kl.endswith("pwd") or kl == "pwd"


def _is_user_key(k: str, user_hints) -> bool:
    kl = k.lower()
    if kl.endswith("id"):          # UserId / intUserId / recordId are NOT the username field
        return False
    return kl == "user" or any(kl.endswith(h) for h in user_hints)


def _fill_params(template: dict, user_keys, pw_keys, user: str, pw: str) -> dict:
    # pw_keys/user_keys kept for API compatibility; matching is boundary/suffix-aware so that
    # bookkeeping params like UserId=0 are never mistaken for the credential fields.
    user_hints = tuple(user_keys) + ("username", "email", "stremail")
    out = dict(template)
    for k in list(out.keys()):
        if _is_pw_key(k):
            out[k] = pw
        elif _is_user_key(k, user_hints):
            out[k] = user
    return out


def raw_differential(client, endpoint: str, param_template: dict, creds: list[tuple[str, str]],
                     *, method: str = "GET", fake_user: str = DEFAULT_FAKE_USER,
                     user_keys=("user", "email", "login", "uid"),
                     pw_keys=("pass", "pwd")) -> AppProbe:
    """Replay the discovered login endpoint directly for FAKE + each cred, over `client`
    (an httpx.Client — injectable, so tests pass a MockTransport-backed one). Password value
    for the baseline/creds comes from the creds list; the baseline reuses the first cred's pw."""
    probe = AppProbe(target=endpoint, api_endpoint=endpoint, api_method=method)
    baseline_pw = creds[0][1] if creds else "x"
    ordered = [("FAKE", fake_user, baseline_pw)] + [(u, u, p) for (u, p) in creds]
    fake_attempt: Attempt | None = None
    for label, user, pw in ordered:
        params = _fill_params(param_template, user_keys, pw_keys, user, pw)
        a = Attempt(label=label, username=user, lens="raw")
        try:
            r = client.request(method, endpoint, params=params)
            a.status = r.status_code
            a.body = (r.text or "")[:300]
            a.logged_in = _looks_logged_in(r.status_code, a.body, moved=False, token_present=False)
        except Exception as exc:  # noqa: BLE001
            a.note = f"request error: {exc}"[:120]
        probe.attempts.append(a)
        if label == "FAKE":
            fake_attempt = a
        elif fake_attempt is not None:
            probe.raw_verdicts[label] = classify_verdict(a, fake_attempt)
    return probe


# --------------------------------------------------------------------------- #
# Browser lens (Playwright, lazy) — discovery + differential                  #
# --------------------------------------------------------------------------- #

def discover_and_probe(target: str, creds: list[tuple[str, str]], *,
                       fake_user: str = DEFAULT_FAKE_USER, timeout_ms: int = 30000,
                       out_dir: str | None = None,
                       token_key: str | None = None,
                       token_storage: str = "session") -> AppProbe:
    """Drive the real login page for FAKE + each credential and classify.

    Discovers the login form (first visible password field + its username peer + a submit
    control), captures the real login API call's status+body, a visible error snippet, and a
    screenshot per attempt. For SPA token logins, pass token_key (e.g. "JWTToken") to detect a
    successful login via the token landing in session/localStorage (the positive-control path).
    """
    import os
    from playwright.sync_api import sync_playwright  # lazy

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    probe = AppProbe(target=target)
    ordered = [("FAKE", fake_user, creds[0][1] if creds else "x")] + [(u, u, p) for (u, p) in creds]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
        fake_attempt: Attempt | None = None
        for i, (label, user, pw) in enumerate(ordered):
            ctx = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()
            a = Attempt(label=label, username=user, lens="browser")
            api_hits: list = []

            def _on_resp(resp, _hits=api_hits):
                try:
                    u = resp.url.lower()
                    if any(h in u for h in _AUTH_URL_HINTS) and "logout" not in u:
                        try:
                            body = resp.text()[:300]
                        except Exception:  # noqa: BLE001
                            body = "<no-body>"
                        _hits.append((resp.url, resp.status, resp.request.method, body))
                except Exception:  # noqa: BLE001
                    pass

            page.on("response", _on_resp)
            try:
                page.goto(target, wait_until="domcontentloaded", timeout=timeout_ms)
                pw_loc = page.locator("input[type=password]:visible").first
                pw_loc.wait_for(state="visible", timeout=timeout_ms)
                user_loc = page.locator(
                    "input[type=text]:visible, input[type=email]:visible, "
                    "input:not([type]):visible").first
                # discover selectors / hashing once, on the FAKE pass
                if i == 0:
                    probe.login_url = page.url
                    content = page.content()
                    probe.client_side_hashing = bool(_CLIENT_HASH_HINTS.search(content))
                    if probe.client_side_hashing:
                        probe.notes.append("client-side password handling detected — raw lens unreliable")
                user_loc.fill(user, timeout=timeout_ms)
                pw_loc.fill(pw, timeout=timeout_ms)
                before = page.url
                submit = page.locator(
                    "input[type=submit]:visible, button[type=submit]:visible, "
                    "button:visible, [onclick*='ogin']:visible").first
                try:
                    submit.click(timeout=min(timeout_ms, 8000))
                except Exception:  # noqa: BLE001
                    pw_loc.press("Enter")
                page.wait_for_timeout(5000)

                moved = page.url != before and "login" not in page.url.lower()
                token_present = False
                if token_key:
                    store = "localStorage" if token_storage.startswith("local") else "sessionStorage"
                    try:
                        token_present = bool(page.evaluate(
                            "a => !!window[a.s] && !!window[a.s].getItem(a.k)",
                            {"s": store, "k": token_key}))
                    except Exception:  # noqa: BLE001
                        token_present = False
                # pick the most login-ish API hit
                pick = None
                for url, st, meth, body in api_hits:
                    if "authuser" in url.lower() or "authenticate" in url.lower():
                        pick = (url, st, body); break
                if not pick and api_hits:
                    pick = (api_hits[-1][0], api_hits[-1][1], api_hits[-1][3])
                if pick:
                    if i == 0:
                        probe.api_endpoint = re.sub(r"(?i)(pass(word)?|pwd)=[^&]*", r"\1=***", pick[0])
                        probe.api_method = "GET" if "?" in pick[0] else "POST"
                    a.status = pick[1]
                    a.body = pick[2]
                try:
                    a.visible_error = page.evaluate(
                        "()=>{for(const s of ['.noty_text','.validation-summary-errors',"
                        "'#lblError','.alert','[class*=error]']){const e=document.querySelector(s);"
                        "if(e&&e.innerText&&e.offsetParent)return e.innerText.trim().slice(0,120);}"
                        "return '';}")
                except Exception:  # noqa: BLE001
                    a.visible_error = ""
                a.logged_in = _looks_logged_in(a.status, a.body, moved=moved,
                                               token_present=token_present)
                if out_dir:
                    shot = os.path.join(out_dir, f"{_safe(target)}_{label}.png")
                    page.screenshot(path=shot)
                    a.screenshot = shot
            except Exception as exc:  # noqa: BLE001
                a.note = f"probe error: {exc}"[:140]
            finally:
                ctx.close()
            probe.attempts.append(a)
            if label == "FAKE":
                fake_attempt = a
            elif fake_attempt is not None:
                probe.verdicts[label] = classify_verdict(a, fake_attempt)
        browser.close()
    return probe


def _safe(url: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", urlsplit(url).netloc or url)[:40]
