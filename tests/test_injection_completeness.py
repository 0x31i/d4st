"""NoSQL / LDAP / server-side HPP native probes — mock-verified, safe (read-only GET, auth-skip)."""
import http.server
import socketserver
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from d4st.activetests import run_hpp_checks, run_ldap_checks, run_nosql_checks

httpx = pytest.importorskip("httpx")

_BASE = "<html>" + ("x" * 300) + "</html>"


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
        vals = [v for vs in q.values() for v in vs]
        if sp.path == "/nosql":
            if any("'" in v for v in vals):
                return self._send(500, "MongoError: unterminated string literal near '")
            return self._send(200, _BASE)
        if sp.path == "/ldap":
            if any(")(" in v for v in vals):
                return self._send(500, "LDAP: error code 53 - Bad search filter")
            return self._send(200, _BASE)
        if sp.path == "/hpp":                     # reflect ALL q values (concatenation)
            return self._send(200, "<p>" + ",".join(q.get("q", [])) + "</p>")
        if sp.path == "/hpp-safe":                # first-wins (no concatenation)
            return self._send(200, "<p>" + (q.get("q", [""])[0]) + "</p>")
        return self._send(200, _BASE)             # /safe: never errors


@pytest.fixture()
def server():
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_nosql_error_based(server):
    f = run_nosql_checks(None, server, [f"{server}/nosql?name=foo"], delay=0)
    assert len(f) == 1 and f[0]["category"] == "nosql-injection"


def test_nosql_no_fp(server):
    assert run_nosql_checks(None, server, [f"{server}/safe?name=foo"], delay=0) == []


def test_ldap_error_based(server):
    f = run_ldap_checks(None, server, [f"{server}/ldap?name=foo"], delay=0)
    assert len(f) == 1 and f[0]["category"] == "ldap-injection"


def test_ldap_no_fp(server):
    assert run_ldap_checks(None, server, [f"{server}/safe?name=foo"], delay=0) == []


def test_hpp_concatenation_detected(server):
    f = run_hpp_checks(None, server, [f"{server}/hpp?q=foo"], delay=0)
    assert len(f) == 1 and f[0]["category"] == "parameter-pollution"


def test_hpp_first_wins_no_fp(server):
    assert run_hpp_checks(None, server, [f"{server}/hpp-safe?q=foo"], delay=0) == []


def test_all_skip_auth_endpoints(server):
    u = f"{server}/login?name=foo'"
    assert run_nosql_checks(None, server, [u], delay=0) == []
    assert run_ldap_checks(None, server, [f"{server}/account/reset?q=foo"], delay=0) == []
