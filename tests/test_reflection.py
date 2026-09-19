"""Reflected-input surface map — canary-verified, context-aware."""
import http.server
import socketserver
import threading

import pytest

from d4st.activetests import run_reflection_checks

httpx = pytest.importorskip("httpx")


class _H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        from urllib.parse import parse_qs, urlsplit
        sp = urlsplit(self.path)
        q = parse_qs(sp.query)
        val = q.get("q", [""])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        if sp.path == "/js":
            body = f"<html><script>var x='{val}';</script></html>"      # JS context
        elif sp.path == "/reflect":
            body = f"<html><body>Hello {val}</body></html>"             # HTML context
        else:
            body = "<html><body>no reflection here</body></html>"       # not reflected
        self.wfile.write(body.encode())


class _Session:
    headers: dict = {}

    def cookie_header(self, base):
        return ""


@pytest.fixture()
def server():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_reflection_html_context(server):
    base = f"http://127.0.0.1:{server}/"
    out = run_reflection_checks(_Session(), base, [f"http://127.0.0.1:{server}/reflect?q=hello"])
    assert len(out) == 1
    assert out[0]["type"] == "reflected-input"
    assert "html context" in out[0]["detail"]


def test_reflection_js_context_is_medium(server):
    base = f"http://127.0.0.1:{server}/"
    out = run_reflection_checks(_Session(), base, [f"http://127.0.0.1:{server}/js?q=hello"])
    assert len(out) == 1
    assert out[0]["severity"] == "medium"
    assert "javascript context" in out[0]["detail"]


def test_no_reflection_no_finding(server):
    base = f"http://127.0.0.1:{server}/"
    out = run_reflection_checks(_Session(), base, [f"http://127.0.0.1:{server}/none?q=hello"])
    assert out == []
