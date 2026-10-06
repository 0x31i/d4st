"""Unit tests for the DOM-free token minter (httpx path). No network: httpx is monkeypatched."""

from __future__ import annotations

import pytest

from d4st.auth.minter import _dig, _find_jwt, _subst, mint_token
from d4st.auth.profile import AuthProfile

_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkYXN0In0.sig"


def test_dig_dotted_path():
    assert _dig({"data": {"accessToken": "x"}}, "data.accessToken") == "x"
    assert _dig({"a": [{"t": "y"}]}, "a.0.t") == "y"
    assert _dig({"a": 1}, "a.b") is None
    assert _dig({"a": 1}, "") == {"a": 1}


def test_find_jwt_walks_structure():
    assert _find_jwt({"outer": {"token": _JWT}}) == _JWT
    assert _find_jwt(["noise", {"k": _JWT}]) == _JWT
    assert _find_jwt({"k": "not a jwt"}) is None


def test_subst_recurses():
    assert _subst({"q": "u={user}&p={pass}"}, "alice", "pw") == {"q": "u=alice&p=pw"}
    assert _subst(["{user}", {"x": "{pass}"}], "a", "b") == ["a", {"x": "b"}]


class _FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.text = "" if isinstance(payload, dict) else str(payload)

        class _Jar:
            jar: list = []
        self.cookies = _Jar()

    def json(self):
        if isinstance(self._payload, dict):
            return self._payload
        raise ValueError("not json")


class _FakeClient:
    last = {}

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def request(self, method, url, **kwargs):
        _FakeClient.last = {"method": method, "url": url, **kwargs}
        return _FakeResp({"Token": _JWT, "status": True})


def _profile(**over):
    base = dict(
        name="t", type="spa-token-api", login_url="{base}/",
        username="u", password="p",
        auth_api={"url": "{base}/api/Login/AuthUser", "method": "GET",
                  "cred_style": "plaintext-query",
                  "request": {"query": "UserName={user}&Password={pass}"},
                  "token_json_path": "Token"},
        token={"key": "Token", "storage": "session", "header": "Authorization", "scheme": "Bearer "},
    )
    base.update(over)
    return AuthProfile(**base)


def test_mint_plaintext_query(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "Client", _FakeClient)
    sess = mint_token(_profile(), "https://app.example", username="alice", password="s p@ce")
    # token lifted into the Authorization header and into sessionStorage
    assert sess.headers["Authorization"] == f"Bearer {_JWT}"
    assert sess.session_storage["Token"] == _JWT
    # creds url-encoded into the query string (space + @ escaped)
    assert "UserName=alice" in _FakeClient.last["url"]
    assert "s%20p%40ce" in _FakeClient.last["url"]


def test_mint_json_body(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "Client", _FakeClient)
    prof = _profile(auth_api={"url": "{base}/api/Login/AuthUser", "method": "POST",
                              "cred_style": "json-body",
                              "request": {"json": {"u": "{user}", "p": "{pass}"}},
                              "token_json_path": "Token"})
    mint_token(prof, "https://app.example", username="bob", password="pw")
    assert _FakeClient.last["json"] == {"u": "bob", "p": "pw"}
    assert _FakeClient.last["method"] == "POST"


def test_mint_unfilled_cred_style_errors():
    prof = _profile(auth_api={"url": "{base}/x", "cred_style": "TODO"})
    with pytest.raises(RuntimeError, match="not filled in"):
        mint_token(prof, "https://app.example", username="u", password="p")


def test_mint_no_auth_api_errors():
    prof = AuthProfile(name="form-only")
    with pytest.raises(RuntimeError, match="no auth_api.url"):
        mint_token(prof, "https://app.example", username="u", password="p")
