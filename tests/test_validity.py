"""Session-validity gate: token-aware handling (the fix for JWT-SPAs that `launch` used to
reject by defaulting to a 'Logout' marker + raw GET of the SPA shell)."""

from d4st.auth import validity
from d4st.auth.session import Session

_JWT = "aaaaaaaaaa.bbbbbbbbbbbbbbbbbbbb.cccccccccccccccc"  # header.payload.sig, >40 chars


def _bearer_session():
    return Session(name="t", origin="https://spa.test",
                   headers={"Authorization": f"Bearer {_JWT}"})


def _storage_token_session():
    return Session(name="t", origin="https://spa.test",
                   session_storage={"JWTToken": _JWT})


def _cookie_session():
    return Session(name="t", origin="https://app.test",
                   storage_state={"cookies": [{"name": "SESS", "value": "x",
                                               "domain": "app.test", "path": "/"}]})


# ----- token detection ----------------------------------------------------- #

def test_bearer_header_is_token_auth():
    assert validity.session_is_token_auth(_bearer_session()) is True


def test_jwt_in_session_storage_is_token_auth():
    assert validity.session_is_token_auth(_storage_token_session()) is True


def test_plain_cookie_session_is_not_token_auth():
    assert validity.session_is_token_auth(_cookie_session()) is False


# ----- is_session_valid branching (is_valid stubbed; no network/browser) ---- #

def test_token_session_valid_when_probe_ok(monkeypatch):
    monkeypatch.setattr(validity, "is_valid", lambda *a, **k: (True, "ok (rendered) at /"))
    ok, note = validity.is_session_valid(_bearer_session(), "https://spa.test/")
    assert ok is True and "token session" in note


def test_token_session_valid_when_render_unavailable(monkeypatch):
    # THE REGRESSION: a valid JWT-SPA session must NOT be rejected just because the shell
    # lacks a 'Logout' marker / playwright isn't available. Token presence => proceed.
    monkeypatch.setattr(validity, "is_valid",
                        lambda *a, **k: (False, "render probe unavailable (no playwright)"))
    ok, note = validity.is_session_valid(_storage_token_session(), "https://spa.test/")
    assert ok is True and "present" in note


def test_token_session_rejected_only_on_positive_logout(monkeypatch):
    monkeypatch.setattr(validity, "is_valid",
                        lambda *a, **k: (False, "redirected to login: https://spa.test/login"))
    ok, _ = validity.is_session_valid(_bearer_session(), "https://spa.test/")
    assert ok is False


def test_explicit_marker_is_honored(monkeypatch):
    seen = {}
    def fake(sess, url, marker, timeout=15.0, render=False):
        seen["marker"] = marker
        return (True, "marker present")
    monkeypatch.setattr(validity, "is_valid", fake)
    ok, _ = validity.is_session_valid(_bearer_session(), "https://spa.test/app", marker="Sign out")
    assert ok is True and seen["marker"] == "Sign out"


def test_cookie_session_delegates_to_raw_heuristic(monkeypatch):
    monkeypatch.setattr(validity, "is_valid", lambda *a, **k: (True, "ok 200 at /app"))
    ok, note = validity.is_session_valid(_cookie_session(), "https://app.test/app")
    assert ok is True and note == "ok 200 at /app"
