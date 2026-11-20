"""Tests for the intercepting-proxy engine (d4st/proxy.py).

Two layers:
  - GUARD/UNIT tests (always run): the _check_send chain — scope-lock, destructive-block, DELETE
    hard-refusal, and the pluggable policy hook — plus drop's intercept-then-drop enforcement
    (mitmproxy #4711). These use a tiny fake flow/store and never touch mitmproxy or the network.
  - A LOOPBACK SMOKE test (skipped-pending-install if mitmproxy is absent / Python < 3.10): start
    the proxy on a local port, confirm it listens, make ONE request THROUGH it to a local
    python -m http.server, list/get the captured flow, then stop. No external target.
"""

from __future__ import annotations

import socket
import sys

import pytest

from d4st import proxy as P

# The guard/unit tests below import NO mitmproxy (proxy.py defers that import into start()), so they
# run on the 3.9 core floor too. Only the loopback smoke test needs mitmproxy; it is
# skipped-pending-install when the extra is absent (Python < 3.10 / not installed).
_HAVE_MITM = False
if sys.version_info >= (3, 10):
    try:
        import mitmproxy as _m  # noqa: F401
        _HAVE_MITM = True
    except Exception:  # noqa: BLE001
        _HAVE_MITM = False

requires_mitm = pytest.mark.skipif(
    not _HAVE_MITM,
    reason="skipped-pending-install: mitmproxy not importable (needs Python >= 3.10)")


# --------------------------------------------------------------------------- guard unit tests

class _FakeReq:
    def __init__(self, method="GET", url="http://app.example.com/x"):
        self.method = method
        self.pretty_url = url


class _FakeFlow:
    def __init__(self, fid="f1", method="GET", url="http://app.example.com/x",
                 intercepted=False, killable=True):
        self.id = fid
        self.request = _FakeReq(method, url)
        self.intercepted = intercepted
        self.killable = killable
        self.killed = False

    def kill(self):
        self.killed = True


def _engine(scope=None, policy=None):
    e = P.ProxyEngine(scope_hosts=scope, policy=policy)
    return e


def test_sendcheck_scope_lock():
    e = _engine(scope=["example.com"])
    e._check_send("GET", "http://app.example.com/ok")           # subdomain in scope -> allowed
    with pytest.raises(ValueError, match="out of scope"):
        e._check_send("GET", "http://evil.test/x")


def test_sendcheck_delete_hard_refused_even_with_manual():
    e = _engine()
    with pytest.raises(ValueError, match="refused outright"):
        e._check_send("DELETE", "http://app.example.com/thing/1", manual_destructive=True)


def test_sendcheck_write_verb_needs_manual():
    e = _engine()
    with pytest.raises(ValueError, match="not read-only"):
        e._check_send("POST", "http://app.example.com/items")
    e._check_send("POST", "http://app.example.com/items", manual_destructive=True)   # authorized


def test_sendcheck_destructive_path_needs_manual():
    e = _engine()
    with pytest.raises(ValueError, match="not read-only"):
        e._check_send("GET", "http://app.example.com/account/delete")


def test_sendcheck_session_destroying_hard_refused():
    e = _engine()
    with pytest.raises(ValueError, match="refused outright"):
        e._check_send("GET", "http://app.example.com/logout", manual_destructive=True)


def test_policy_hook_runs_and_can_block():
    seen = []

    def policy(method, url):
        seen.append((method, url))
        if "blocked" in url:
            raise ValueError("policy veto")

    e = _engine(policy=policy)
    e._check_send("GET", "http://app.example.com/ok")
    assert seen == [("GET", "http://app.example.com/ok")]
    with pytest.raises(ValueError, match="policy veto"):
        e._check_send("GET", "http://app.example.com/blocked")


def test_drop_requires_paused_flow():
    """#4711: drop is reliable only on a PAUSED flow — a non-intercepted flow is refused."""
    import asyncio
    e = _engine()
    e.store.add(_FakeFlow(fid="live", intercepted=False))
    with pytest.raises(ValueError, match="not paused"):
        asyncio.run(e.drop("live"))


def test_drop_kills_paused_flow():
    import asyncio
    e = _engine()
    f = _FakeFlow(fid="paused", intercepted=True)
    e.store.add(f)
    res = asyncio.run(e.drop("paused"))
    assert res["killed"] and f.killed


def test_flowstore_stable_id_upsert_and_eviction():
    s = P.FlowStore(max_flows=2)
    s.add(_FakeFlow(fid="a"))
    s.add(_FakeFlow(fid="a"))           # upsert — still one
    assert s.count() == 1
    s.add(_FakeFlow(fid="b"))
    s.add(_FakeFlow(fid="c"))           # evicts "a"
    assert s.count() == 2
    assert s.get("a") is None and s.get("c") is not None


# --------------------------------------------------------------------------- loopback smoke test

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@requires_mitm
def test_loopback_capture_smoke(tmp_path):
    """Start proxy -> confirm listening -> make one request THROUGH it to a local http.server ->
    list/get the flow -> stop. No external target."""
    import http.server
    import socketserver
    import threading
    import urllib.request

    # 1. throwaway local origin server
    class _Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"hello-through-proxy")

    origin_port = _free_port()
    httpd = socketserver.TCPServer(("127.0.0.1", origin_port), _Quiet)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    proxy_port = _free_port()
    bp = P.BackgroundProxy(listen_host="127.0.0.1", listen_port=proxy_port, scope_hosts=[])
    try:
        info = bp.start()
        assert info["listen"] == f"127.0.0.1:{proxy_port}"
        # 2. listener is actually accepting
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=2):
            pass
        # 3. one HTTP request THROUGH the proxy to the local origin
        origin = f"http://127.0.0.1:{origin_port}/probe"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"}))
        body = opener.open(origin, timeout=10).read()
        assert body == b"hello-through-proxy"
        # 4. the flow was captured, listable, and serializes to the evidence shape
        rows = bp.list_flows()
        assert any(r["url"] and r["url"].endswith("/probe") for r in rows), rows
        fid = next(r["id"] for r in rows if (r["url"] or "").endswith("/probe"))
        ex = bp.get_flow(fid)
        assert ex["request"]["method"] == "GET"
        assert ex["request"]["url"].endswith("/probe")
        assert ex["response"]["status"] == 200
        assert "repro" in ex and ex["repro"].startswith("curl")
    finally:
        bp.stop()
        httpd.shutdown()
