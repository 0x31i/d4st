"""Session-validity probe + refresh gate.

Before fanning a session out to the scanners, confirm it is still logged in by hitting a
known authenticated URL and asserting a logged-in marker. If it fails (session expired /
redirect to login), the caller re-captures. This is what keeps 'launch' a single command:
the tool self-heals the session instead of silently scanning logged-out.
"""

from __future__ import annotations

from .profile import AuthProfile
from .session import Session


def is_valid(session: Session, url: str, marker: str | None,
             timeout: float = 15.0, render: bool = False) -> tuple[bool, str]:
    """Return (ok, note). ok=True when the marker is present (or, if no marker given, when
    the response is a 2xx that did not redirect to a login page).

    ``render=True`` drives a headless browser with the captured session (cookies +
    localStorage) instead of a raw HTTP GET — required for SPAs whose logged-in marker
    is rendered client-side and never appears in the shell HTML."""
    if render:
        return _is_valid_rendered(session, url, marker, timeout)
    import httpx
    cookie = session.cookie_header(url)
    headers = {"Cookie": cookie} if cookie else {}
    headers.update(session.headers)
    try:
        r = httpx.get(url, headers=headers, follow_redirects=True, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return False, f"probe error: {exc}"
    final = str(r.url)
    if marker:
        if marker in r.text:
            return True, f"marker present at {final} ({r.status_code})"
        return False, f"marker {marker!r} absent at {final} ({r.status_code})"
    if r.status_code >= 400:
        return False, f"status {r.status_code} at {final}"
    if "login" in final.lower():
        return False, f"redirected to login: {final}"
    return True, f"ok {r.status_code} at {final}"


def _is_valid_rendered(session: Session, url: str, marker: str | None,
                       timeout: float = 15.0) -> tuple[bool, str]:
    from urllib.parse import urlsplit
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001
        return False, f"render probe unavailable ({exc}); install playwright"
    origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
    tmo = int(timeout * 1000)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(storage_state=session.storage_state or None,
                                      ignore_https_errors=True)
            # restore sessionStorage (storage_state omits it) + any bearer header
            init = session.session_storage_init_script()
            if init:
                ctx.add_init_script(init)
            if session.headers:
                try:
                    ctx.set_extra_http_headers(session.headers)
                except Exception:
                    pass
            page = ctx.new_page()
            # SPA warm-up: bootstrap the origin before deep-linking (same reason as capture).
            if origin.rstrip("/") != url.rstrip("/"):
                try:
                    page.goto(origin, wait_until="networkidle", timeout=tmo)
                except Exception:
                    pass
            page.goto(url, wait_until="networkidle", timeout=tmo)
            final = page.url
            if marker:
                try:
                    page.wait_for_function(
                        "m => document.body && document.body.innerText.includes(m)",
                        arg=marker, timeout=tmo)
                    browser.close()
                    return True, f"marker present (rendered) at {final}"
                except Exception:
                    browser.close()
                    if "login" in final.lower():
                        return False, f"redirected to login: {final}"
                    return False, f"marker {marker!r} absent (rendered) at {final}"
            browser.close()
            if "login" in final.lower():
                return False, f"redirected to login: {final}"
            return True, f"ok (rendered) at {final}"
    except Exception as exc:  # noqa: BLE001
        return False, f"render probe error: {exc}"


def probe_profile(session: Session, profile: AuthProfile, base: str,
                  timeout: float = 15.0) -> tuple[bool, str]:
    render = bool(profile.validity.get("render")) if isinstance(profile.validity, dict) else False
    return is_valid(session, profile.validity_url(base), profile.validity_marker(),
                    timeout, render=render)


def session_is_token_auth(session: Session) -> bool:
    """True when the session carries a bearer/custom auth header or a JWT-looking value in
    sessionStorage — i.e. a token-auth SPA whose logged-in state lives in a token, not a
    server-rendered 'Logout' link. For these, a raw GET of the SPA shell is NOT a valid
    logged-in signal (the shell is identical logged-in or out)."""
    for k in (session.headers or {}):
        if k.lower() == "authorization" or k.lower().startswith("x-") and "auth" in k.lower():
            return True
    for v in (session.session_storage or {}).values():
        if isinstance(v, str) and v.count(".") == 2 and len(v) > 40:  # JWT-ish: header.payload.sig
            return True
    return False


def is_session_valid(session: Session, url: str, marker: str | None = None,
                     *, timeout: float = 15.0, render: bool | None = None) -> tuple[bool, str]:
    """Validity gate that understands token-auth sessions (the fix for JWT-SPAs that `launch`
    previously rejected by defaulting to a 'Logout' text marker + raw GET).

    - An explicit ``marker`` is always honored (rendered if ``render`` or token-auth).
    - Otherwise, a **token-auth** session is valid when the token is present: the scanners
      replay that bearer to the API, so presence is the actionable signal (an expired token
      just yields 401s mid-scan, same as any session going stale). We still try a rendered
      probe for extra confidence, but never fail a present-token session on an ambiguous SPA
      shell — only on a positive bounce to a ``/login`` path.
    - A non-token (cookie) session with no marker falls back to the raw 2xx/not-login heuristic.
    """
    token_auth = session_is_token_auth(session)
    if render is None:
        render = token_auth  # SPAs must be rendered to mean anything
    if marker:
        return is_valid(session, url, marker, timeout, render=render)
    if token_auth:
        ok, note = is_valid(session, url, None, timeout, render=render)
        if ok:
            return True, f"token session; {note}"
        if "redirected to login" in note:   # positive logged-out signal
            return False, f"token session but {note}"
        # ambiguous (render unavailable / marker-less SPA shell): trust token presence
        return True, "token session (bearer/JWT present; will replay to API)"
    return is_valid(session, url, marker, timeout, render=render)


# =============================================================================================
# Configurable session-validity MODE (D4ST_SESSION_VALIDITY_MODE) — fail-closed.
#
# The legacy gate (is_session_valid) does a RENDERED portal-cookie probe: it asserts a logged-in
# browser marker (e.g. a '/accounts/logout' link). That is correct for cookie/session (web-app)
# engagements, but WRONG for an API-auth engagement whose real authentication is HTTP Basic Auth
# in the Authorization header rather than a portal cookie: there the rendered probe blocks a
# perfectly valid API pass because there is no browser cookie session to find.
#
# The mode lets an operator pick the right check PER ENGAGEMENT, while keeping the gate
# fail-closed (an unknown mode, or a basic-auth mode that cannot DEMONSTRATE authentication,
# ABORTS exactly like the rendered check does — the gate NEVER silently skips validation):
#   - "rendered"   (DEFAULT) : unchanged legacy behavior (rendered portal marker / token-aware).
#   - "basic-auth"           : prove the configured Basic creds gate the endpoint (401 -> 200).
#   - "both"                 : rendered AND basic-auth must BOTH pass.
# =============================================================================================

SESSION_VALIDITY_MODES = ("rendered", "basic-auth", "both")

# Spelling tolerance: never maps to a WEAKER-than-asked check, only normalizes punctuation.
_MODE_ALIASES = {
    "rendered": "rendered",
    "basic-auth": "basic-auth",
    "basic_auth": "basic-auth",
    "basicauth": "basic-auth",
    "basic": "basic-auth",
    "both": "both",
}


class SessionValidityConfigError(ValueError):
    """D4ST_SESSION_VALIDITY_MODE / the Basic-Auth probe config is malformed or incomplete.

    The run ABORTS (fail-closed). This is the session-validity analog of ExcludeConfigError:
    a bad/empty config must never silently disable the gate."""


def normalize_validity_mode(raw: str | None) -> str:
    """Normalize + validate the validity-mode string. Default is 'rendered' (legacy behavior).

    FAIL-CLOSED: an unknown value RAISES SessionValidityConfigError rather than silently
    degrading to a weaker (or no) check."""
    mode = (raw or "rendered").strip().lower()
    if mode not in _MODE_ALIASES:
        raise SessionValidityConfigError(
            f"unknown session-validity mode {raw!r}; expected one of "
            f"{', '.join(SESSION_VALIDITY_MODES)}")
    return _MODE_ALIASES[mode]


def basic_auth_probe(url: str, username: str, password: str,
                     *, timeout: float = 15.0) -> tuple[bool, str]:
    """Fail-closed HTTP Basic-Auth validity probe. Returns (ok, note).

    Proves the endpoint actually GATES on the configured Basic credentials by requiring the
    unauthenticated->authenticated transition:
      * WITHOUT the Authorization header -> endpoint MUST reject with 401 (the Basic challenge)
      * WITH the Basic header            -> endpoint MUST return 2xx (authorized)

    Every other outcome fails closed (ok=False) — we never assume a valid session:
      * no-auth already 2xx  -> auth is NOT actually required (suspicious / wrong endpoint); ABORT
      * no-auth not 401      -> endpoint does not issue a Basic challenge; ABORT
      * with-auth not 2xx    -> credentials rejected / endpoint broken; ABORT
      * transport error      -> ABORT
      * missing url/creds    -> ABORT (misconfigured)

    Redirects are NOT followed: a protected resource answers 200 directly when authorized, and a
    302 (e.g. to a login page) is ambiguous and must not be laundered into a 2xx.
    """
    if not url or not username or not password:
        return False, "basic-auth probe not configured (need endpoint + username + password)"
    import base64

    import httpx

    token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    try:
        unauth = httpx.get(url, follow_redirects=False, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return False, f"basic-auth probe error (no-auth request): {exc}"
    if unauth.status_code != 401:
        return False, (
            f"no-auth request to {url} returned {unauth.status_code}, expected 401 — endpoint "
            f"does not require Basic auth; refusing to assume a valid session")
    try:
        authed = httpx.get(url, headers={"Authorization": f"Basic {token}"},
                           follow_redirects=False, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return False, f"basic-auth probe error (authed request): {exc}"
    if 200 <= authed.status_code < 300:
        return True, f"basic-auth 401->{authed.status_code} transition confirmed at {url}"
    return False, (
        f"authed request to {url} returned {authed.status_code}, expected 2xx — credentials "
        f"rejected or endpoint broken")


def validate_session(session: Session, cfg, *, probe_url: str | None = None,
                     marker: str | None = None, render: bool | None = None,
                     timeout: float = 15.0) -> tuple[bool, str]:
    """Mode-aware, fail-closed session-validity gate. Returns (ok, note).

    ``cfg.session_validity_mode`` selects the check (default 'rendered' = the legacy
    is_session_valid() behavior, byte-unchanged for existing/web engagements):
      * 'rendered'   -> is_session_valid(session, probe_url, marker, render)
      * 'basic-auth' -> basic_auth_probe() against cfg.session_validity_probe_url with
                        cfg.basic_auth_user / cfg.basic_auth_pass, requiring 401->200.
      * 'both'       -> rendered AND basic-auth must BOTH pass.

    FAIL-CLOSED: an unknown mode RAISES; a basic-auth/both mode with missing probe config, or a
    basic-auth probe that cannot demonstrate the 401->200 transition, returns (False, ...) so the
    caller ABORTS exactly as the rendered check does. The new modes NEVER skip validation."""
    mode = normalize_validity_mode(getattr(cfg, "session_validity_mode", None))

    def _rendered() -> tuple[bool, str]:
        return is_session_valid(session, probe_url, marker, timeout=timeout, render=render)

    def _basic() -> tuple[bool, str]:
        url = getattr(cfg, "session_validity_probe_url", None)
        user = getattr(cfg, "basic_auth_user", None)
        pw = getattr(cfg, "basic_auth_pass", None)
        if not url or not user or not pw:
            return False, (
                "basic-auth validity mode requires D4ST_SESSION_VALIDITY_URL, "
                "D4ST_BASIC_AUTH_USER and D4ST_BASIC_AUTH_PASS (missing/empty)")
        return basic_auth_probe(url, user, pw, timeout=timeout)

    if mode == "rendered":
        return _rendered()
    if mode == "basic-auth":
        return _basic()
    # both: require BOTH; report the first that fails.
    ok_r, note_r = _rendered()
    if not ok_r:
        return False, f"[both] rendered check failed: {note_r}"
    ok_b, note_b = _basic()
    if not ok_b:
        return False, f"[both] basic-auth check failed: {note_b}"
    return True, f"[both] rendered ok ({note_r}); basic-auth ok ({note_b})"
