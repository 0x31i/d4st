"""Permanence lock for the unauthenticated-API-data-exposure + broken-auth detectors.

This test pins the behavior that caught the real-world class of finding: an /api endpoint that
returns bulk records or credential fields to an unauthenticated caller, and an endpoint that still
serves data when the auth header is stripped. If a refactor ever re-gates or breaks these
detectors, this test fails in CI and the change cannot merge. Uses a real in-process HTTP server so
the detectors exercise their actual httpx request path.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from d4st.apiexposure import scan_api_exposure
from d4st.auth.authz import _auth_header_name, run_authz
from d4st.auth.session import Session

_REAL_TOKEN = "realtoken-abc123"
_BULK = [{"id": 1, "name": "Alice", "dept": "IT"}, {"id": 2, "name": "Bob", "dept": "HR"}]
_CREDS = {"username": "svc", "password": "hunter2-secret", "ok": True}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        tok = self.headers.get("X-App-Token", "")
        if path == "/api/users":           # bulk data, NO auth enforced -> exposure + broken-auth
            return self._json(202, _BULK)   # 202 (not 200): locks 2xx acceptance (this API style uses 202)
        if path == "/api/creds":           # credential field, NO auth enforced -> cred exposure
            return self._json(202, _CREDS)  # 202 as well
        if path == "/api/secure":          # PROPERLY protected -> negative control
            if tok == _REAL_TOKEN:
                return self._json(200, _BULK)
            return self._json(401, {"error": "unauthorized"})
        if path == "/api/xmlusers":        # XML-serialized bulk -> XML fallback must still catch it
            body = (b"<ArrayOfRec><Rec><id>1</id><name>Alice</name></Rec>"
                    b"<Rec><id>2</id><name>Bob</name></Rec></ArrayOfRec>")
            self.send_response(202)
            self.send_header("Content-Type", "application/xml; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return self._json(404, {"error": "not found"})


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    yield f"http://{host}:{port}"
    httpd.shutdown()


def _urls(base):
    return [f"{base}/api/users", f"{base}/api/creds", f"{base}/api/secure"]


def test_apiexposure_flags_unauth_bulk_and_credentials(server):
    out = scan_api_exposure(_urls(server), cookie="", authed=False)
    by_url = {f["url"].split("?")[0]: f for f in out}
    # bulk records returned with NO auth -> excessive data exposure (HIGH)
    assert f"{server}/api/users" in by_url
    assert by_url[f"{server}/api/users"]["category"] == "excessive-data-exposure"
    # credential field returned with NO auth -> credential dump (CRITICAL class)
    assert f"{server}/api/creds" in by_url
    assert by_url[f"{server}/api/creds"]["category"] == "unauth-credential-exposure"
    # properly-protected endpoint (401 unauth) must NOT be flagged
    assert f"{server}/api/secure" not in by_url


def test_apiexposure_catches_xml_bulk(server):
    # an API that serves (or content-negotiates to) XML must not hide bulk data behind the format
    out = scan_api_exposure([f"{server}/api/xmlusers"], cookie="", authed=False)
    by_url = {f["url"].split("?")[0]: f for f in out}
    assert f"{server}/api/xmlusers" in by_url
    assert by_url[f"{server}/api/xmlusers"]["category"] == "excessive-data-exposure"


def test_authz_flags_broken_auth_on_custom_header(server):
    sess = Session(name="t", origin=server,
                   headers={"X-App-Token": _REAL_TOKEN})
    # the detector must target the custom auth header, not default to Authorization
    assert _auth_header_name(sess) == "X-App-Token"
    out = run_authz(sess, server, _urls(server), delay=0)
    broken = {f["url"].split("?")[0]: f for f in out if f["type"] == "broken-auth"}
    # token stripped -> still 200 with data on these two -> broken auth
    assert f"{server}/api/users" in broken
    assert f"{server}/api/creds" in broken
    # the protected endpoint returns 401 without the token -> NOT broken
    assert f"{server}/api/secure" not in broken


def test_authz_noauth_actually_strips_custom_header(server):
    # a session whose ONLY auth is a custom header must yield a no-auth request that omits it,
    # otherwise /api/secure would look "broken" when it is in fact enforcing.
    sess = Session(name="t", origin=server,
                   headers={"X-App-Token": _REAL_TOKEN})
    out = run_authz(sess, server, [f"{server}/api/secure"], delay=0)
    assert not [f for f in out if f["type"] == "broken-auth"], \
        "custom auth header was not stripped in the no-auth probe (false negative risk)"
