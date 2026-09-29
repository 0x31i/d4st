"""XPath injection detector (error-based + boolean-based) — mock-server verified, no real target.

Confirms: error-based fires on an XPath parser error absent from baseline; boolean-based fires on
a stark TRUE/FALSE differential; a non-injectable endpoint yields no finding (no FP); auth
endpoints are skipped (account-lockout safety)."""
import http.server
import socketserver
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from d4st.activetests import run_xpath_checks

httpx = pytest.importorskip("httpx")

_BIG = "<html><body>" + ("<div class='rec'>record</div>" * 40) + "</body></html>"   # >200B
_SMALL = "<html><body>no results</body></html>"


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        sp = urlsplit(self.path)
        q = parse_qs(sp.query, keep_blank_values=True)
        if sp.path == "/vuln":
            v = q.get("name", [""])[0]
            if v.count("'") % 2 == 1:          # unbalanced quote -> parser error
                return self._send(500, "Fatal error: Invalid XPath expression: unclosed token")
            return self._send(200, _BIG)
        if sp.path == "/bool":
            v = q.get("q", [""])[0].lower()
            if "and '1'='2" in v:              # FALSE contradiction -> empty
                return self._send(200, _SMALL)
            return self._send(200, _BIG)        # baseline, lone-quote, and TRUE -> populated
        if sp.path == "/login":                # auth endpoint (must be skipped)
            return self._send(500, "Invalid XPath expression")
        return self._send(200, _BIG)            # /safe -> identical regardless of input


@pytest.fixture()
def server():
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_error_based_detected(server):
    f = run_xpath_checks(None, server, [f"{server}/vuln?name=foo"], delay=0)
    assert len(f) == 1
    assert f[0]["category"] == "xpath" and f[0]["verified"] is True
    assert "error-based" in f[0]["detail"] or "parser error" in f[0]["detail"]


def test_boolean_based_detected(server):
    f = run_xpath_checks(None, server, [f"{server}/bool?q=foo"], delay=0)
    assert len(f) == 1
    assert f[0]["category"] == "xpath" and f[0]["severity"] == "high"


def test_safe_endpoint_no_fp(server):
    f = run_xpath_checks(None, server, [f"{server}/safe?q=foo"], delay=0)
    assert f == []


def test_auth_endpoint_skipped(server):
    # /login would 'error' but must never be probed (lockout safety) -> no finding.
    f = run_xpath_checks(None, server, [f"{server}/login?name=foo"], delay=0)
    assert f == []
