"""run_verb_tampering severity calibration: a GET-case bypass that returns a BODY is a HIGH data
leak; a HEAD-only bypass (no body) is a MEDIUM gate bypass; an allowed OPTIONS preflight is NOT a
bypass. Also: prefer the body-returning variant over HEAD even when HEAD is also accepted."""
import types
import pytest

from d4st import activetests as A


class _R:
    def __init__(self, status, body=b""):
        self.status_code = status
        self.content = body
        self.text = body.decode() if isinstance(body, (bytes, bytearray)) else str(body)
        self.headers = {}
        self.request = types.SimpleNamespace(method="GET", url="http://x", headers={})


class _Client:
    """Scripts responses by (method) for a single endpoint."""
    def __init__(self, script):
        self.script = script
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def get(self, url, headers=None):
        return self.script["GET_AUTH"] if headers and headers.get("Cookie") == "sid=1" else self.script["GET_NOAUTH"]
    def request(self, method, url, headers=None):
        authed = bool(headers and headers.get("Cookie") == "sid=1")
        if method == "GET":                      # exact baseline GET (authed oracle vs unauth baseline)
            return self.script["GET_AUTH"] if authed else self.script["GET_NOAUTH"]
        if method.strip().upper() == "GET":      # a case variant: "Get" / "get" / "GET "
            return self.script.get("GETCASE", _R(404))
        return self.script.get(method.strip().upper(), _R(404))


class _Session:
    headers = {}
    def cookie_header(self, base): return "sid=1"


def _patch(monkeypatch, script):
    fake = types.SimpleNamespace(Client=lambda *a, **k: _Client(script))
    monkeypatch.setitem(__import__("sys").modules, "httpx", fake)
    # neutralise pacing
    monkeypatch.setattr(A, "pace", lambda *a, **k: None, raising=False)


BASE = "https://t.example"
URL = "https://t.example/api/Thing/Get/"


def _run(monkeypatch, script):
    _patch(monkeypatch, script)
    return A.run_verb_tampering(_Session(), BASE, [URL], delay=0, max_endpoints=10)


def test_getcase_body_is_high_dataleak(monkeypatch):
    out = _run(monkeypatch, {
        "GET_AUTH": _R(200, b"owner data"), "GET_NOAUTH": _R(401),
        "GETCASE": _R(200, b"X" * 500),   # unauth 'get'/'Get'/'GET ' -> returns a body
        "HEAD": _R(200, b""),
    })
    bypass = [f for f in out if f["type"] == "verb-tampering-auth-bypass"]
    assert len(bypass) == 1
    assert bypass[0]["severity"] == "high"
    assert "LEAKS DATA" in bypass[0]["detail"]


def test_head_only_is_medium_gate_bypass(monkeypatch):
    out = _run(monkeypatch, {
        "GET_AUTH": _R(200, b"owner data"), "GET_NOAUTH": _R(401),
        "GETCASE": _R(401),           # case variants stay rejected
        "HEAD": _R(200, b""),        # only HEAD bypasses, no body
    })
    bypass = [f for f in out if f["type"] == "verb-tampering-auth-bypass"]
    assert len(bypass) == 1
    assert bypass[0]["severity"] == "medium"
    assert "no response body" in bypass[0]["detail"]
    assert bypass[0]["method"].upper() == "HEAD"


def test_options_allowed_is_not_a_bypass(monkeypatch):
    out = _run(monkeypatch, {
        "GET_AUTH": _R(200, b"owner data"), "GET_NOAUTH": _R(401),
        "GETCASE": _R(401), "HEAD": _R(401),
        "OPTIONS": _R(200, b"allow"),   # benign preflight — must NOT be a bypass
    })
    bypass = [f for f in out if f["type"] == "verb-tampering-auth-bypass"]
    assert bypass == []
