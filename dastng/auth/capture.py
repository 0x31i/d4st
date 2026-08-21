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
                     timeout_ms: int = 30000) -> Session:
    from playwright.sync_api import sync_playwright

    base = profile.resolve_base(base)
    login_url = profile.fmt(profile.login_url, base)
    user, pw = profile.creds()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        ctx = browser.new_context()
        page = ctx.new_page()
        page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
        page.fill(profile.username_selector, user, timeout=timeout_ms)
        page.fill(profile.password_selector, pw, timeout=timeout_ms)

        if profile.totp.get("enabled"):
            code = totp_from_env(profile.totp.get("seed_env", ""))
            sel = profile.totp.get("selector")
            if code and sel:
                page.fill(sel, code, timeout=timeout_ms)

        page.click(profile.submit_selector, timeout=timeout_ms)
        page.wait_for_load_state("networkidle", timeout=timeout_ms)

        marker = profile.success.get("body_contains")
        url_contains = profile.success.get("url_contains")
        body = page.content()
        ok = True
        if url_contains and url_contains not in page.url:
            ok = False
        if marker and marker not in body:
            ok = False
        if not ok:
            state = ctx.storage_state()
            browser.close()
            raise RuntimeError(
                f"login did not reach the success marker for profile {profile.name!r} "
                f"(url={page.url}); captured {len(state.get('cookies', []))} cookies anyway"
            )

        state = ctx.storage_state()
        browser.close()

    session = Session(name=profile.name, origin=base, storage_state=state,
                      meta={"profile": profile.name, "mode": "scripted",
                            "security": security or ""})
    _apply_post_login_cookies(session, profile, base, security)
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
        state = ctx.storage_state()
        browser.close()

    session = Session(name=profile.name, origin=base, storage_state=state,
                      meta={"profile": profile.name, "mode": "interactive",
                            "security": security or ""})
    _apply_post_login_cookies(session, profile, base, security)
    return session
