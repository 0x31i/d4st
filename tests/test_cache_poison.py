"""Web cache poisoning detector — mock-verified, SAFE (unique cache-buster, confirm-by-refetch).

/vuln: caches unkeyed on X-Forwarded-Host (poison persists for the cache key) -> detected.
/safe: reflects the header but never caches -> clean re-fetch has no canary -> no finding (no FP).
/norefl: never reflects the header -> no finding. Auth endpoints are skipped."""
import http.server
import socketserver
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from d4st.activetests import run_cache_poisoning_checks

httpx = pytest.importorskip("httpx")

_CACHE: dict = {}   # cb -> cached body (simulates an unkeyed shared cache on /vuln)


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        sp = urlsplit(self.path)
        cb = parse_qs(sp.query).get("cb", [""])[0]
        xfh = self.headers.get("X-Forwarded-Host")
        base = "<html><link rel=canonical href='https://real.example/x'></html>"
        if sp.path == "/vuln":
            if xfh:                                   # poison request: reflect + cache under cb
                body = f"<html><link rel=canonical href='https://{xfh}/x'></html>"
                _CACHE[cb] = body
            else:                                     # clean request: serve cached (poisoned) copy
                body = _CACHE.get(cb, base)
        elif sp.path == "/safe":
            body = f"<html><link href='https://{xfh}/x'></html>" if xfh else base  # reflect, no cache
        else:                                          # /norefl: never reflect the header
            body = base
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b)


@pytest.fixture()
def server():
    _CACHE.clear()
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_vulnerable_cache_poisoning_detected(server):
    f = run_cache_poisoning_checks(None, server, [f"{server}/vuln"], delay=0)
    assert len(f) == 1
    assert f[0]["category"] == "web-cache-poisoning" and f[0]["verified"] is True
    assert f[0]["severity"] == "high"


def test_reflected_but_not_cached_no_fp(server):
    f = run_cache_poisoning_checks(None, server, [f"{server}/safe"], delay=0)
    assert f == []


def test_no_reflection_no_finding(server):
    f = run_cache_poisoning_checks(None, server, [f"{server}/norefl"], delay=0)
    assert f == []


def test_auth_endpoint_skipped(server):
    f = run_cache_poisoning_checks(None, server, [f"{server}/login/vuln"], delay=0)
    assert f == []
