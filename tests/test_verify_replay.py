"""Verify-stage replay modules for the differentiator classes (BFLA/verb-tampering, HPP,
PII/secret disclosure) and the core rule that verify must never downgrade a detector that already
proved a finding. Covers the regression where verify_finding() reset detector verified=True to None
for every class it lacked a replay module for."""
import types
import pytest

from d4st import engagement as E
from d4st.engagement import Finding


class _Resp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text
        self.headers = {}


def _fake_httpx(monkeypatch, *, get=None, request=None):
    fake = types.SimpleNamespace()
    fake.get = get or (lambda *a, **k: _Resp())
    fake.request = request or (lambda m, *a, **k: _Resp())
    monkeypatch.setitem(__import__("sys").modules, "httpx", fake)
    return fake


# ---- core rule: no downgrade of detector-proven findings in classes with no replay module --------

def test_unknown_class_preserves_detector_proof():
    f = Finding(tool="authz", category="broken-object-level-authorization", url="https://x/api/1",
                verified=True, detection="authz active test")
    out = E.verify_finding(f, cookie="")
    assert out.verified is True  # was being clobbered to None before the fix
    assert "no separate replay module" in out.verify_note


def test_unknown_class_unproven_stays_none():
    f = Finding(tool="misc", category="some-weird-class", url="https://x/", verified=False)
    out = E.verify_finding(f, cookie="")
    assert out.verified is None
    assert "no independent replay" in out.verify_note


# ---- verb-tampering / BFLA independent replay ----------------------------------------------------

def test_verbtamper_reconfirms(monkeypatch):
    def request(method, *a, **k):
        return _Resp(401) if method == "GET" else _Resp(200)
    _fake_httpx(monkeypatch, request=request)
    f = Finding(tool="verbtamper", category="broken-access-control", url="https://x/api/p",
                method="HEAD", verified=True, detection="verbtamper active test")
    out = E.verify_finding(f, cookie="")
    assert out.verified is True
    assert "bypass holds on replay" in out.verify_note


def test_verbtamper_not_reconfirmed_keeps_detector(monkeypatch):
    # baseline no longer protected on replay (both 200) — don't erase the detector's proof
    _fake_httpx(monkeypatch, request=lambda m, *a, **k: _Resp(200))
    f = Finding(tool="verbtamper", category="broken-access-control", url="https://x/api/p",
                method="HEAD", verified=True, detection="verbtamper active test")
    out = E.verify_finding(f, cookie="")
    assert out.verified is True  # preserved, not refuted
    assert "not reconfirmed" in out.verify_note


# ---- HPP differential replay ---------------------------------------------------------------------

def test_hpp_divergence_confirms(monkeypatch):
    calls = {"n": 0}
    def get(url, *a, **k):
        calls["n"] += 1
        return _Resp(200, "A" * 100) if calls["n"] == 1 else _Resp(500, "boom")
    _fake_httpx(monkeypatch, get=get)
    f = Finding(tool="hpp", category="parameter-pollution", url="https://x/s?q=1", param="q",
                verified=True)
    out = E.verify_finding(f, cookie="")
    assert out.verified is True
    assert "diverges" in out.verify_note


def test_hpp_no_divergence_keeps_detector(monkeypatch):
    _fake_httpx(monkeypatch, get=lambda url, *a, **k: _Resp(200, "same body"))
    f = Finding(tool="hpp", category="parameter-pollution", url="https://x/s?q=1", param="q",
                verified=True)
    out = E.verify_finding(f, cookie="")
    assert out.verified is True  # detector proof retained
    assert "replay not reconfirmed" in out.verify_note


# ---- PII/secret live re-fetch (additive only) ----------------------------------------------------

def test_pii_live_confirmed(monkeypatch):
    _fake_httpx(monkeypatch, get=lambda url, *a, **k: _Resp(200, "contact admin@example.com here"))
    f = Finding(tool="jsdisclosure", category="pii-disclosure", url="https://x/app.js",
                evidence="email: admin@example.com", verified=True)
    out = E.verify_finding(f, cookie="")
    assert out.verified is True
    assert "live-confirmed" in out.verify_note


def test_pii_refetch_absent_is_inconclusive_not_fp(monkeypatch):
    _fake_httpx(monkeypatch, get=lambda url, *a, **k: _Resp(200, "nothing sensitive now"))
    f = Finding(tool="jsdisclosure", category="pii-disclosure", url="https://x/app.js",
                evidence="email: admin@example.com", verified=True)
    out = E.verify_finding(f, cookie="")
    assert out.verified is True  # never refuted on a mere re-fetch miss
    assert "did not contain the needle" in out.verify_note


def test_len_similar():
    assert E._len_similar(100, 110) is True
    assert E._len_similar(100, 500) is False
