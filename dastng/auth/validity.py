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
             timeout: float = 15.0) -> tuple[bool, str]:
    """Return (ok, note). ok=True when the marker is present (or, if no marker given, when
    the response is a 2xx that did not redirect to a login page)."""
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


def probe_profile(session: Session, profile: AuthProfile, base: str,
                  timeout: float = 15.0) -> tuple[bool, str]:
    return is_valid(session, profile.validity_url(base), profile.validity_marker(), timeout)
