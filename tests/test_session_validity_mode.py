"""D4ST_SESSION_VALIDITY_MODE — configurable, fail-closed session-validity self-test.

The engagement-start gate defaults to a RENDERED portal-cookie probe (assert a logged-in browser
marker). That is right for cookie/session web apps but WRONG for an API-auth engagement whose real
authentication is HTTP Basic Auth in the Authorization header — there the rendered probe blocks a
perfectly valid API pass. This adds an opt-in 'basic-auth' (and 'both') mode that proves the
configured Basic creds gate the endpoint (401 -> 200), while keeping the gate fail-closed:

  * default stays 'rendered' and byte-unchanged for existing engagements (regression guard);
  * an unknown mode ABORTS (never silently degrades to a weaker check);
  * a basic-auth/both mode with missing endpoint/creds ABORTS at Config construction;
  * basic-auth passes ONLY on the unauth-401 -> auth-2xx transition; 200-without-auth (auth not
    actually required) and 401-with-auth (creds rejected) and transport errors all ABORT;
  * 'both' requires rendered AND basic-auth.

No real/external host is ever contacted: httpx.get is monkeypatched and the rendered probe is
stubbed, exactly like tests/test_validity.py.
"""

from __future__ import annotations

import pytest

from d4st.auth import validity
from d4st.auth.session import Session
from d4st.auth.validity import SessionValidityConfigError
from d4st.config import Config

_PROBE = "https://api.test/accounts/me"
_USER = "scanner@client.test"
_PASS = "s3cr3t"


@pytest.fixture(autouse=True)
def _clean_validity_env(monkeypatch):
    """Start each test from a known-clean validity env so ambient shell config can't bleed in."""
    for k in ("D4ST_SESSION_VALIDITY_MODE", "D4ST_SESSION_VALIDITY_URL",
              "D4ST_BASIC_AUTH_USER", "D4ST_BASIC_AUTH_PASS"):
        monkeypatch.delenv(k, raising=False)
    yield


def _cookie_session():
    return Session(name="t", origin="https://app.test",
                   storage_state={"cookies": [{"name": "SESS", "value": "x",
                                               "domain": "app.test", "path": "/"}]})


class _Resp:
    def __init__(self, status_code: int):
        self.status_code = status_code


def _fake_get(no_auth_status: int, auth_status: int, record: list | None = None):
    """A stand-in for httpx.get that answers by whether the Basic Authorization header is present."""
    def _get(url, headers=None, follow_redirects=False, timeout=15.0):
        has_auth = bool(headers and "Authorization" in headers)
        if record is not None:
            record.append((url, dict(headers or {}), follow_redirects, has_auth))
        return _Resp(auth_status if has_auth else no_auth_status)
    return _get


def _basic_cfg(**over):
    kw = {"session_validity_mode": "basic-auth", "session_validity_probe_url": _PROBE,
          "basic_auth_user": _USER, "basic_auth_pass": _PASS}
    kw.update(over)
    return Config(**kw)


# ----------------------------- mode normalization (fail-closed) -------------------------------- #

def test_normalize_default_is_rendered():
    assert validity.normalize_validity_mode(None) == "rendered"
    assert validity.normalize_validity_mode("") == "rendered"
    assert validity.normalize_validity_mode("  RENDERED ") == "rendered"


def test_normalize_aliases():
    for raw in ("basic-auth", "basic_auth", "basicauth", "BASIC", " Basic "):
        assert validity.normalize_validity_mode(raw) == "basic-auth"
    assert validity.normalize_validity_mode("both") == "both"


def test_normalize_unknown_mode_aborts():
    # FAIL-CLOSED: garbage must RAISE, never fall through to a weaker/no check.
    with pytest.raises(SessionValidityConfigError):
        validity.normalize_validity_mode("disabled")
    with pytest.raises(SessionValidityConfigError):
        validity.normalize_validity_mode("off")


# ----------------------------- Config parsing + fail-closed construction ----------------------- #

def test_config_default_mode_rendered(monkeypatch):
    cfg = Config.from_env()
    assert cfg.session_validity_mode == "rendered"
    # rendered needs no basic-auth inputs
    assert cfg.session_validity_probe_url is None


def test_config_empty_env_mode_rendered(monkeypatch):
    monkeypatch.setenv("D4ST_SESSION_VALIDITY_MODE", "")  # set but empty == default
    assert Config.from_env().session_validity_mode == "rendered"


def test_config_parses_basic_auth_mode(monkeypatch):
    monkeypatch.setenv("D4ST_SESSION_VALIDITY_MODE", "basic-auth")
    monkeypatch.setenv("D4ST_SESSION_VALIDITY_URL", _PROBE)
    monkeypatch.setenv("D4ST_BASIC_AUTH_USER", _USER)
    monkeypatch.setenv("D4ST_BASIC_AUTH_PASS", _PASS)
    cfg = Config.from_env()
    assert cfg.session_validity_mode == "basic-auth"
    assert cfg.session_validity_probe_url == _PROBE
    assert cfg.basic_auth_user == _USER and cfg.basic_auth_pass == _PASS


def test_config_basic_auth_missing_config_aborts(monkeypatch):
    # THE fail-closed guard: basic-auth mode with no endpoint/creds must ABORT at construction.
    monkeypatch.setenv("D4ST_SESSION_VALIDITY_MODE", "basic-auth")
    with pytest.raises(SessionValidityConfigError):
        Config.from_env()
    # partial config (url only, no creds) still aborts
    with pytest.raises(SessionValidityConfigError):
        Config(session_validity_mode="basic-auth", session_validity_probe_url=_PROBE)


def test_config_unknown_mode_aborts(monkeypatch):
    monkeypatch.setenv("D4ST_SESSION_VALIDITY_MODE", "none")
    with pytest.raises(SessionValidityConfigError):
        Config.from_env()


def test_config_both_missing_config_aborts():
    with pytest.raises(SessionValidityConfigError):
        Config(session_validity_mode="both", session_validity_probe_url=_PROBE,
               basic_auth_user=_USER)  # password missing


# ----------------------------- basic_auth_probe (401 -> 200 transition) ------------------------ #

def test_basic_auth_probe_passes_on_401_then_200(monkeypatch):
    import httpx
    rec: list = []
    monkeypatch.setattr(httpx, "get", _fake_get(401, 200, rec))
    ok, note = validity.basic_auth_probe(_PROBE, _USER, _PASS)
    assert ok is True and "401->200" in note
    # proves it actually sent BOTH a no-auth and a Basic-auth request, redirects NOT followed
    assert len(rec) == 2 and rec[0][3] is False and rec[1][3] is True
    assert all(r[2] is False for r in rec)


def test_basic_auth_probe_aborts_when_no_auth_already_200(monkeypatch):
    # auth not actually required => suspicious (wrong endpoint / open resource); fail closed.
    import httpx
    monkeypatch.setattr(httpx, "get", _fake_get(200, 200))
    ok, note = validity.basic_auth_probe(_PROBE, _USER, _PASS)
    assert ok is False and "expected 401" in note


def test_basic_auth_probe_aborts_when_auth_rejected_401(monkeypatch):
    # creds rejected: unauth 401 and authed STILL 401 => fail closed.
    import httpx
    monkeypatch.setattr(httpx, "get", _fake_get(401, 401))
    ok, note = validity.basic_auth_probe(_PROBE, _USER, _PASS)
    assert ok is False and "expected 2xx" in note


def test_basic_auth_probe_aborts_on_403_with_auth(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "get", _fake_get(401, 403))
    ok, _ = validity.basic_auth_probe(_PROBE, _USER, _PASS)
    assert ok is False


def test_basic_auth_probe_aborts_on_transport_error(monkeypatch):
    import httpx

    def _boom(*a, **k):
        raise httpx.ConnectError("refused")
    monkeypatch.setattr(httpx, "get", _boom)
    ok, note = validity.basic_auth_probe(_PROBE, _USER, _PASS)
    assert ok is False and "probe error" in note


def test_basic_auth_probe_aborts_when_unconfigured():
    assert validity.basic_auth_probe("", _USER, _PASS)[0] is False
    assert validity.basic_auth_probe(_PROBE, "", _PASS)[0] is False
    assert validity.basic_auth_probe(_PROBE, _USER, "")[0] is False


# ----------------------------- validate_session dispatch (fail-closed) ------------------------- #

def test_rendered_mode_delegates_unchanged(monkeypatch):
    # The default path must be byte-unchanged: validate_session just forwards to is_session_valid
    # with exactly the same args a legacy call-site passed.
    seen = {}

    def _fake_isv(session, url, marker=None, *, timeout=15.0, render=None):
        seen.update(session=session, url=url, marker=marker, timeout=timeout, render=render)
        return (True, "LEGACY-OK")
    monkeypatch.setattr(validity, "is_session_valid", _fake_isv)
    sess = _cookie_session()
    cfg = Config()  # default -> rendered
    ok, note = validity.validate_session(sess, cfg, probe_url="https://app.test/x",
                                         marker="Logout", render=True)
    assert ok is True and note == "LEGACY-OK"
    assert seen == {"session": sess, "url": "https://app.test/x", "marker": "Logout",
                    "timeout": 15.0, "render": True}


def test_basic_auth_mode_passes_on_transition(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "get", _fake_get(401, 200))
    ok, note = validity.validate_session(_cookie_session(), _basic_cfg())
    assert ok is True and "401->200" in note


def test_basic_auth_mode_aborts_on_200_without_auth(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "get", _fake_get(200, 200))
    ok, _ = validity.validate_session(_cookie_session(), _basic_cfg())
    assert ok is False


def test_basic_auth_mode_aborts_on_rejected_creds(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "get", _fake_get(401, 401))
    ok, _ = validity.validate_session(_cookie_session(), _basic_cfg())
    assert ok is False


def test_basic_auth_mode_does_not_consult_rendered(monkeypatch):
    # basic-auth must NOT fall back to the rendered probe (that would re-introduce the bug).
    import httpx
    monkeypatch.setattr(httpx, "get", _fake_get(401, 200))
    monkeypatch.setattr(validity, "is_session_valid",
                        lambda *a, **k: pytest.fail("rendered probe must not run in basic-auth mode"))
    ok, _ = validity.validate_session(_cookie_session(), _basic_cfg())
    assert ok is True


# ----------------------------- 'both' requires BOTH -------------------------------------------- #

def _both_cfg():
    return Config(session_validity_mode="both", session_validity_probe_url=_PROBE,
                  basic_auth_user=_USER, basic_auth_pass=_PASS)


def test_both_requires_both_pass(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "get", _fake_get(401, 200))
    monkeypatch.setattr(validity, "is_session_valid", lambda *a, **k: (True, "rendered-ok"))
    ok, note = validity.validate_session(_cookie_session(), _both_cfg())
    assert ok is True and "rendered ok" in note and "basic-auth ok" in note


def test_both_aborts_when_rendered_fails(monkeypatch):
    import httpx
    # rendered fails; basic-auth probe must not even be consulted (short-circuit).
    monkeypatch.setattr(httpx, "get",
                        lambda *a, **k: pytest.fail("basic probe must not run once rendered fails"))
    monkeypatch.setattr(validity, "is_session_valid", lambda *a, **k: (False, "no logout marker"))
    ok, note = validity.validate_session(_cookie_session(), _both_cfg())
    assert ok is False and "[both] rendered check failed" in note


def test_both_aborts_when_basic_auth_fails(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "get", _fake_get(401, 401))   # creds rejected
    monkeypatch.setattr(validity, "is_session_valid", lambda *a, **k: (True, "rendered-ok"))
    ok, note = validity.validate_session(_cookie_session(), _both_cfg())
    assert ok is False and "[both] basic-auth check failed" in note
