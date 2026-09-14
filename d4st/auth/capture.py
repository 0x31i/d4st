"""Playwright-based login capture.

Two modes:
- scripted: drive the login form headlessly from the profile recipe (+ TOTP if configured).
  Fully unattended. Works for DVWA (the browser submits the hidden user_token automatically).
- interactive: launch a headed browser, let a human complete login (SSO / push MFA / CAPTCHA),
  then capture the resulting session once. The unattended fallback for auth we cannot script.

Playwright is imported lazily so the rest of the auth module (translators, validity, session
model) works without the browser binaries installed. Install once with:
    python -m playwright install chromium
"""

from __future__ import annotations

from urllib.parse import urlsplit

from .profile import AuthProfile
from .session import Session
from .totp import totp_from_env


def _dump_session_storage(page) -> dict:
    """Snapshot sessionStorage — Playwright's storage_state does NOT include it, and
    token-auth SPAs (EHRM keeps its JWT here) are logged-out without it."""
    try:
        return page.evaluate(
            "() => { const o = {}; for (let i = 0; i < sessionStorage.length; i++)"
            " { const k = sessionStorage.key(i); o[k] = sessionStorage.getItem(k); } return o; }"
        ) or {}
    except Exception:
        return {}


def _apply_bearer(session: Session, profile: AuthProfile) -> None:
    """Extract the auth token named by profile.token and set it as an HTTP header so the
    HTTP-level scanners (ZAP/httpx/nuclei) replay it. sessionStorage first, then localStorage."""
    tok = getattr(profile, "token", None) or {}
    key = tok.get("key")
    if not key:
        return
    val = None
    if tok.get("storage", "session") == "session":
        val = session.session_storage.get(key)
    if val is None:  # fall back to localStorage (carried in storage_state.origins)
        for o in session.storage_state.get("origins", []):
            for item in o.get("localStorage", []):
                if item.get("name") == key:
                    val = item.get("value")
    if val:
        session.headers[tok.get("header", "Authorization")] = f"{tok.get('scheme', 'Bearer ')}{val}"


def _apply_post_login_cookies(session: Session, profile: AuthProfile, base: str,
                              security: str | None) -> None:
    host = urlsplit(base).hostname or ""
    for c in profile.post_login_cookies:
        value = c.get("value", "")
        # allow --security to override the DVWA security cookie
        if security and c.get("name") == "security":
            value = security
        session.set_cookie(c["name"], value, domain=host, path=c.get("path", "/"))


def capture_scripted(profile: AuthProfile, base: str | None = None, *,
                     headless: bool = True, security: str | None = None,
                     username: str | None = None, password: str | None = None,
                     timeout_ms: int = 30000) -> Session:
    from playwright.sync_api import sync_playwright

    base = profile.resolve_base(base)
    login_url = profile.fmt(profile.login_url, base)
    user, pw = profile.creds(username, password)

    origin = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        ctx = browser.new_context()
        page = ctx.new_page()
        # SPA-friendly login: some single-page apps only build the login view after
        # bootstrapping from the app root, so warm up the origin first, then land on
        # the login URL and wait for the form to render before filling.
        if origin.rstrip("/") != login_url.rstrip("/"):
            try:
                page.goto(origin, wait_until="networkidle", timeout=timeout_ms)
            except Exception:
                pass
        page.goto(login_url, wait_until="networkidle", timeout=timeout_ms)
        page.wait_for_selector(profile.username_selector, state="visible", timeout=timeout_ms)
        page.fill(profile.username_selector, user, timeout=timeout_ms)
        page.fill(profile.password_selector, pw, timeout=timeout_ms)

        if profile.totp.get("enabled"):
            code = totp_from_env(profile.totp.get("seed_env", ""))
            sel = profile.totp.get("selector")
            if code and sel:
                page.fill(sel, code, timeout=timeout_ms)

        page.click(profile.submit_selector, timeout=timeout_ms)

        marker = profile.success.get("body_contains")
        url_contains = profile.success.get("url_contains")
        # SPA logins route client-side after an auth XHR that can settle just past
        # networkidle — wait for the success signal(s) instead of checking once.
        try:
            if url_contains:
                page.wait_for_url(f"**{url_contains}**", timeout=timeout_ms)
            if marker:
                page.wait_for_function(
                    "m => document.body && document.body.innerText.includes(m)",
                    arg=marker, timeout=timeout_ms)
        except Exception:
            pass
        page.wait_for_load_state("networkidle", timeout=timeout_ms)

        body = page.content()
        ok = True
        if url_contains and url_contains not in page.url:
            ok = False
        if marker and marker not in body:
            ok = False
        # ROBUST auth-success fallback (kills the transient-redirect false failure): a token-auth
        # SPA can route through an INTERMEDIATE page (e.g. /config/userConfig, a first-login step)
        # before the marker page, or render the marker a beat after our one-shot check — a transient
        # that wrongly failed an otherwise-successful login. The ground truth is the auth TOKEN: if
        # the profile's token key is present in sessionStorage/localStorage and we are OFF the login
        # page, authentication unquestionably succeeded. Accept it even if the page-marker didn't
        # match, and give the SPA a short grace poll for the token to appear.
        if not ok:
            tkey = (getattr(profile, "token", None) or {}).get("key")
            tstore = (getattr(profile, "token", None) or {}).get("storage", "session")
            store_obj = "localStorage" if str(tstore).startswith("local") else "sessionStorage"
            on_login = "/login" in (page.url or "").lower()
            if tkey and not on_login:
                try:
                    page.wait_for_function(
                        "a => !!window[a.s] && !!window[a.s].getItem(a.k)",
                        arg={"s": store_obj, "k": tkey}, timeout=8000)
                    ok = True
                    print(f"[capture] success via {store_obj}.{tkey} present at {page.url} "
                          f"(page-marker not required — transient-redirect tolerant)", flush=True)
                except Exception:  # noqa: BLE001
                    pass
        if not ok:
            state = ctx.storage_state()
            browser.close()
            raise RuntimeError(
                f"login did not reach the success marker for profile {profile.name!r} "
                f"(url={page.url}); captured {len(state.get('cookies', []))} cookies anyway"
            )

        sstore = _dump_session_storage(page)
        state = ctx.storage_state()
        browser.close()

    session = Session(name=profile.name, origin=base, storage_state=state,
                      session_storage=sstore,
                      meta={"profile": profile.name, "mode": "scripted", "security": security or "",
                            "validity_url": profile.validity_url(base),
                            "validity_marker": profile.validity_marker() or ""})
    _apply_post_login_cookies(session, profile, base, security)
    _apply_bearer(session, profile)
    return session


def capture_interactive(profile: AuthProfile, base: str | None = None, *,
                        security: str | None = None, timeout_ms: int = 300000) -> Session:
    """Headed browser; human logs in, then we capture. Waits for the validity marker to
    appear (or times out). For SSO / push MFA / CAPTCHA that cannot be scripted."""
    from playwright.sync_api import sync_playwright

    base = profile.resolve_base(base)
    login_url = profile.fmt(profile.login_url, base)
    marker = profile.validity_marker()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        ctx = browser.new_context()
        page = ctx.new_page()
        page.goto(login_url, wait_until="domcontentloaded")
        if marker:
            # wait until the logged-in marker shows up anywhere in the page
            page.wait_for_function(
                "m => document.body && document.body.innerText.includes(m)",
                arg=marker, timeout=timeout_ms,
            )
        else:
            page.wait_for_timeout(timeout_ms)
        sstore = _dump_session_storage(page)
        state = ctx.storage_state()
        browser.close()

    session = Session(name=profile.name, origin=base, storage_state=state,
                      session_storage=sstore,
                      meta={"profile": profile.name, "mode": "interactive", "security": security or "",
                            "validity_url": profile.validity_url(base),
                            "validity_marker": profile.validity_marker() or ""})
    _apply_post_login_cookies(session, profile, base, security)
    _apply_bearer(session, profile)
    return session
