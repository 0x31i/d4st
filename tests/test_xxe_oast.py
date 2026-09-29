"""Blind XXE OAST adapter — mock-verified. A 'vulnerable' endpoint resolves the external entity
(fetches our OAST listener -> callback), a 'safe' endpoint ignores the DTD (no callback), and auth
endpoints are skipped. No real target; the entity only ever points at our own listener."""
import http.server
import re
import socketserver
import threading

import pytest

from d4st.orchestrator.adapters.base import RunContext
from d4st.orchestrator.adapters.xxe_oast import XxeOastAdapter, xxe_bodies

httpx = pytest.importorskip("httpx")

_SYS = re.compile(r'SYSTEM\s+"([^"]+)"')


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        # /vuln simulates a parser with external entities ENABLED: it resolves SYSTEM urls.
        if self.path.startswith("/vuln") or self.path.startswith("/api/"):
            for u in _SYS.findall(body):
                if u.startswith("http"):
                    try:
                        httpx.get(u, timeout=5)   # the external-entity fetch = the XXE callback
                    except Exception:
                        pass
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.end_headers()
        self.wfile.write(b"<ok/>")


@pytest.fixture()
def target():
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _run(target, seeds):
    ad = XxeOastAdapter()
    ctx = RunContext(target=target, session=None, seed_urls=seeds,
                     options={"oast_host_ip": "127.0.0.1", "oast_settle": 1, "http_timeout": 6})
    return ad.run(ctx)


def test_payloads_target_only_our_listener():
    # Safety invariant: no file:// and no internal host — only the given callback url.
    bodies = xxe_bodies("http://127.0.0.1:9999/tok")
    joined = "\n".join(bodies)
    assert "file://" not in joined
    assert joined.count("http://127.0.0.1:9999/tok") == len(bodies)


def test_vulnerable_endpoint_detected(target):
    res = _run(target, [f"{target}/vuln"])
    assert res.ok
    assert len(res.findings) == 1
    assert res.findings[0]["type"] == "xxe"
    assert "oast-callback" in res.findings[0]["channel"]


def test_safe_endpoint_no_finding(target):
    res = _run(target, [f"{target}/safe"])
    assert res.ok
    assert res.findings == []


def test_auth_endpoint_skipped(target):
    # /login would be vulnerable-shaped but must never be probed (lockout safety) -> no finding.
    res = _run(target, [f"{target}/login"])
    assert res.findings == []


def test_requires_oast_host_ip(target):
    ad = XxeOastAdapter()
    res = ad.run(RunContext(target=target, seed_urls=[f"{target}/vuln"], options={}))
    assert res.ok is False and "oast_host_ip" in res.note
