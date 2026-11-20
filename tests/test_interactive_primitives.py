"""Unit tests for the interactive engine primitives: replay (Repeater), sweep (Intruder) and
diff_identities (N-way authz diff).

Pins the hardening rules:
  - replay/sweep refuse write verbs by default and STILL hard-refuse DELETE (and session-destroying
    endpoints) even when allow_state_changing=True — a primitive never auto-fires a deletion/logout.
  - sweep's attack-mode expansion counts (sniper / pitchfork / cluster-bomb) and that its throttle
    is invoked once per request.
  - diff_identities returns an N-way verdict shape, and a raising `policy` marks that identity
    BLOCKED (not a network error).

All HTTP is mocked — no real network, no browser.
"""

from __future__ import annotations

import datetime as _dt
import sys
import types

import pytest

from d4st import replay as R
from d4st import sweep as S
from d4st.auth import authz as A


# --------------------------------------------------------------------------- fakes

class _Resp:
    """A minimal stand-in for an httpx.Response that satisfies evidence.exchange/curl/raw_*."""

    def __init__(self, status=200, text="", method="GET", url="https://x/api/thing",
                 req_headers=None, req_content=b""):
        self.status_code = status
        self.text = text
        self.content = text.encode() if isinstance(text, str) else (text or b"")
        self.headers = {"Content-Type": "application/json"}
        self.reason_phrase = "OK"
        self.elapsed = _dt.timedelta(milliseconds=5)
        self.request = types.SimpleNamespace(
            method=method, url=url, headers=req_headers or {}, content=req_content)


def _install_httpx_request(monkeypatch, recorder=None):
    """Replace the module-level `import httpx` used by replay() with a fake exposing .request."""
    def request(method, url, **k):
        if recorder is not None:
            recorder.append((method, url))
        return _Resp(status=200, text='{"ok":true}', method=method, url=url)
    fake = types.SimpleNamespace(request=request)
    monkeypatch.setitem(sys.modules, "httpx", fake)
    return fake


class _FakeClient:
    """Context-manager httpx.Client stand-in; records every request it is asked to send."""

    def __init__(self, responses=None, record=None):
        self._responses = responses or {}
        self._record = record if record is not None else []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def request(self, method, url, **k):
        self._record.append((method, url))
        r = self._responses.get(url)
        if callable(r):
            return r(method, url, **k)
        return r if r is not None else _Resp(status=200, text='{"ok":true}', method=method, url=url)

    # replay_once with no client reuse also constructs a client and calls .request; same surface.
    get = request


def _install_httpx_client(monkeypatch, client):
    fake = types.SimpleNamespace(Client=lambda *a, **k: client)
    monkeypatch.setitem(sys.modules, "httpx", fake)
    return fake


# =========================================================================== replay

def test_replay_refuses_write_verb_by_default():
    for verb in ("POST", "PUT", "PATCH"):
        with pytest.raises(ValueError, match="not read-only"):
            R.replay(verb, "https://x/api/thing")


def test_replay_refuses_delete_by_default():
    with pytest.raises(ValueError):
        R.replay("DELETE", "https://x/api/thing")


def test_replay_allows_get_by_default(monkeypatch):
    _install_httpx_request(monkeypatch)
    out = R.replay("GET", "https://x/api/thing")
    assert out["ok"] is True and out["status"] == 200
    assert "exchange" in out and out["raw_request"].startswith("GET ")


def test_replay_allows_write_on_opt_in(monkeypatch):
    rec = []
    _install_httpx_request(monkeypatch, recorder=rec)
    for verb in ("PUT", "POST", "PATCH"):
        out = R.replay(verb, "https://x/api/thing", body='{"a":1}', allow_state_changing=True)
        assert out["status"] == 200
    assert [m for m, _ in rec] == ["PUT", "POST", "PATCH"]


def test_replay_still_refuses_delete_on_opt_in(monkeypatch):
    _install_httpx_request(monkeypatch)       # must never be reached
    with pytest.raises(ValueError, match="refused outright"):
        R.replay("DELETE", "https://x/api/thing", allow_state_changing=True)


def test_replay_still_refuses_logout_endpoint_on_opt_in(monkeypatch):
    _install_httpx_request(monkeypatch)
    with pytest.raises(ValueError, match="refused outright"):
        R.replay("POST", "https://x/account/logout", allow_state_changing=True)


def test_replay_policy_raise_aborts_before_request(monkeypatch):
    rec = []
    _install_httpx_request(monkeypatch, recorder=rec)

    def policy(method, url):
        raise PermissionError("blocked by driver")

    with pytest.raises(PermissionError):
        R.replay("GET", "https://x/api/thing", policy=policy)
    assert rec == []                          # request was never sent


# =========================================================================== sweep

def test_sweep_sniper_expansion_count():
    # sniper: vary one position at a time -> sum(len(payloads)) across positions
    combos = S._combinations({"a": ["1", "2", "3"], "b": ["x", "y"]}, "sniper", 500)
    assert len(combos) == 5


def test_sweep_pitchfork_expansion_count():
    # pitchfork: lockstep, bounded by the shortest list
    combos = S._combinations({"a": ["1", "2", "3"], "b": ["x", "y"]}, "pitchfork", 500)
    assert len(combos) == 2


def test_sweep_clusterbomb_expansion_count():
    # cluster-bomb: cartesian product
    combos = S._combinations({"a": ["1", "2", "3"], "b": ["x", "y"]}, "cluster-bomb", 500)
    assert len(combos) == 6


def test_sweep_clusterbomb_respects_max_requests():
    combos = S._combinations({"a": ["1", "2", "3"], "b": ["x", "y"]}, "cluster-bomb", 4)
    assert len(combos) == 4


def test_sweep_unknown_mode_raises():
    with pytest.raises(ValueError, match="unknown mode"):
        S._combinations({"a": ["1"]}, "bogus", 500)


def test_sweep_refuses_write_by_default():
    with pytest.raises(ValueError, match="not read-only"):
        S.sweep("POST", "https://x/api/§p§", {"p": ["1"]})


def test_sweep_refuses_delete_on_opt_in():
    with pytest.raises(ValueError, match="refused outright"):
        S.sweep("DELETE", "https://x/api/§p§", {"p": ["1"]}, allow_state_changing=True)


def test_sweep_refuses_destructive_path_url(monkeypatch):
    _install_httpx_client(monkeypatch, _FakeClient())
    with pytest.raises(ValueError, match="destructive/auth path"):
        S.sweep("GET", "https://x/api/delete/§p§", {"p": ["1", "2"]})


class _SpyThrottle:
    """Counts wait()/record() so a test can assert the sweep paced every request."""
    instances = []

    def __init__(self, base_delay=0.15, **k):
        self.waits = 0
        self.records = []
        _SpyThrottle.instances.append(self)

    def wait(self):
        self.waits += 1

    def record(self, status):
        self.records.append(status)


def test_sweep_runs_and_invokes_throttle(monkeypatch):
    _SpyThrottle.instances.clear()
    monkeypatch.setattr(S, "AdaptiveThrottle", _SpyThrottle)
    rec = []
    _install_httpx_client(monkeypatch, _FakeClient(record=rec))
    out = S.sweep("GET", "https://x/api/item?id=§p§", {"p": ["1", "2", "3"]}, base_delay=0.0)
    assert out["total"] == 3 and out["sent"] == 3
    assert len(rec) == 3                      # one request per payload
    spy = _SpyThrottle.instances[0]
    assert spy.waits == 3 and len(spy.records) == 3    # throttle paced + recorded each request


# =========================================================================== diff_identities

class _FakeSession:
    def __init__(self, headers=None):
        self.headers = headers or {"Authorization": "Bearer tok"}

    def cookie_header(self, url):
        return ""


def test_diff_identities_refuses_write_by_default():
    with pytest.raises(ValueError, match="not read-only"):
        A.diff_identities("POST", "https://x/api/obj/1", {"alice": _FakeSession()})


def test_diff_identities_nway_verdict_shape(monkeypatch):
    # owner + 2 others; one non-owner sees the owner's body (bypassed), one is rejected (enforced)
    owner_body = '{"patient":"alice","id":1}'

    def responder(method, url, headers=None, **k):
        auth = (headers or {}).get("Authorization", "")
        if "owner" in auth:
            return _Resp(200, owner_body, method, url)
        if "peer" in auth:
            return _Resp(200, owner_body, method, url)   # sees the SAME object -> bypass
        return _Resp(403, "forbidden", method, url)       # properly rejected

    _install_httpx_client(monkeypatch, _FakeClient(responses={"https://x/api/obj/1": responder}))
    sessions = {
        "owner": _FakeSession({"Authorization": "Bearer owner"}),
        "peer": _FakeSession({"Authorization": "Bearer peer"}),
        "stranger": _FakeSession({"Authorization": "Bearer stranger"}),
    }
    out = A.diff_identities("GET", "https://x/api/obj/1", sessions, owner="owner",
                            delay=0.0, throttle=None)
    assert out["verdict"] == "mixed"          # one bypass + one enforced
    assert out["owner"] == "owner"
    assert {p["name"] for p in out["per_identity"]} == {"owner", "peer", "stranger"}
    peer = next(p for p in out["per_identity"] if p["name"] == "peer")
    stranger = next(p for p in out["per_identity"] if p["name"] == "stranger")
    assert peer["allowed"] and peer["matches_owner"]
    assert not (stranger["allowed"] and stranger["matches_owner"])
    assert len(out["evidence_log"]) == 3


def test_diff_identities_policy_raise_marks_blocked_not_errored(monkeypatch):
    rec = []
    _install_httpx_client(monkeypatch, _FakeClient(record=rec))

    def policy(method, url):
        if method == "GET":
            raise PermissionError("scope policy refused this identity")

    sessions = {"owner": _FakeSession(), "peer": _FakeSession()}
    out = A.diff_identities("GET", "https://x/api/obj/1", sessions, owner="owner",
                            delay=0.0, policy=policy)
    # every identity blocked by policy -> recorded blocked=True, NOT as a network error
    assert rec == []                          # no request was ever sent
    for p in out["per_identity"]:
        assert p["blocked"] is True
        assert p["error"] is None
        assert p["status"] is None
    assert out["verdict"] == "enforced"       # no bypass observed (all blocked)


def test_diff_identities_network_error_marks_errored_not_blocked(monkeypatch):
    def boom(method, url, **k):
        raise ConnectionError("connection reset")

    _install_httpx_client(monkeypatch,
                          _FakeClient(responses={"https://x/api/obj/1": boom}))
    sessions = {"owner": _FakeSession(), "peer": _FakeSession()}
    out = A.diff_identities("GET", "https://x/api/obj/1", sessions, owner="owner", delay=0.0)
    for p in out["per_identity"]:
        assert p["blocked"] is False
        assert p["error"] and "connection reset" in p["error"]
