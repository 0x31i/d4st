"""Suspicious input transformation — SSTI eval + string-escape, with HTML-encoding FP guard."""
import html
import http.server
import socketserver
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from d4st.activetests import run_transformation_checks

httpx = pytest.importorskip("httpx")

_TEMPLATES = ["{{419*823}}", "${419*823}", "#{419*823}", "<%=419*823%>", "{419*823}"]


class _H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        sp = urlsplit(self.path)
        val = parse_qs(sp.query).get("q", [""])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        if sp.path == "/ssti":
            for w in _TEMPLATES:            # emulate a template engine evaluating the expression
                val = val.replace(w, "344837")
            out = val
        elif sp.path == "/escape":          # string-context escaping (SQL/JS)
            out = val.replace("\\", "\\\\").replace("'", "\\'")
        elif sp.path == "/safe":            # correct HTML output-encoding (must NOT be flagged)
            out = html.escape(val, quote=True)
        else:                               # plain verbatim reflection
            out = val
        self.wfile.write(f"<html><body>{out}</body></html>".encode())


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


def test_ssti_expression_evaluated(server):
    base = f"http://127.0.0.1:{server}/"
    out = run_transformation_checks(_Session(), base, [f"http://127.0.0.1:{server}/ssti?q=x"])
    assert len(out) == 1
    assert out[0]["type"] == "server-side-template-injection"
    assert out[0]["severity"] == "high"


def test_string_escape_transformation(server):
    base = f"http://127.0.0.1:{server}/"
    out = run_transformation_checks(_Session(), base, [f"http://127.0.0.1:{server}/escape?q=x"])
    assert len(out) == 1
    assert out[0]["type"] == "suspicious-input-transformation"
    assert out[0]["severity"] == "medium"


def test_html_encoding_not_flagged(server):
    base = f"http://127.0.0.1:{server}/"
    out = run_transformation_checks(_Session(), base, [f"http://127.0.0.1:{server}/safe?q=x"])
    assert out == [], "HTML output-encoding is correct behavior, not a suspicious transformation"


def test_plain_reflection_not_flagged(server):
    base = f"http://127.0.0.1:{server}/"
    out = run_transformation_checks(_Session(), base, [f"http://127.0.0.1:{server}/plain?q=x"])
    assert out == []
