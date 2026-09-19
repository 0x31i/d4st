"""Client-side HTTP parameter pollution (CSPP) active detector — canary-verified."""
import html
import http.server
import socketserver
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from d4st.activetests import run_cspp_checks

httpx = pytest.importorskip("httpx")


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        sp = urlsplit(self.path)
        val = parse_qs(sp.query).get("q", [""])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        if sp.path == "/vuln":
            body = f'<a href="/next?ref={val}">go</a>'          # raw reflection = vulnerable
        else:
            body = f'<a href="/next?ref={html.escape(val, quote=True)}">go</a>'  # encoded = safe
        self.wfile.write(f"<html><body>{body}</body></html>".encode())


class _Session:
    headers: dict = {}

    def cookie_header(self, base):
        return ""


@pytest.fixture()
def server():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_cspp_true_positive(server):
    base = f"http://127.0.0.1:{server}/"
    out = run_cspp_checks(_Session(), base, [f"http://127.0.0.1:{server}/vuln?q=hello"])
    assert len(out) == 1
    assert out[0]["category"] == "client-side-param-pollution"
    assert out[0]["verified"] is True


def test_cspp_no_false_positive_when_encoded(server):
    base = f"http://127.0.0.1:{server}/"
    out = run_cspp_checks(_Session(), base, [f"http://127.0.0.1:{server}/safe?q=hello"])
    assert out == []
