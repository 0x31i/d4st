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
