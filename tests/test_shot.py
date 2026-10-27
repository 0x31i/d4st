"""Tests for the headless-Chrome screenshot primitive (d4st/shot.py).

Two layers:
  - GUARD/UNIT tests (always run): the policy gate (both return styles), the ordering property
    (policy is consulted BEFORE Playwright is imported — a security property), and the pure
    PNG->ShotResult assembly (sha256 of the exact bytes + UTC capture timestamp). None of these
    touch a browser.
  - A LOOPBACK SMOKE test (skipped-pending-install if Playwright/Chromium is absent): serve a tiny
    HTML page from a local http.server on 127.0.0.1, capture it, and assert a non-empty PNG with a
    matching title. No external target.
"""

from __future__ import annotations

import hashlib
import http.server
import os
import socketserver
import threading
from datetime import datetime

import pytest

from d4st import shot as S


# --------------------------------------------------------------------------- playwright availability

def _have_playwright() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001
        return False
    try:
        with sync_playwright() as p:
            path = p.chromium.executable_path
            return bool(path) and os.path.exists(path)
    except Exception:  # noqa: BLE001
        return False


_HAVE_PW = _have_playwright()
requires_playwright = pytest.mark.skipif(
    not _HAVE_PW, reason="skipped-pending-install: Playwright/Chromium not available")


# --------------------------------------------------------------------------- policy gate / ordering

def test_policy_bool_deny_raises_permission_error():
    with pytest.raises(PermissionError):
        S.capture("http://127.0.0.1:1/x", policy=lambda method, url: False)


def test_policy_tuple_deny_surfaces_reason():
    with pytest.raises(PermissionError) as exc:
        S.capture("http://127.0.0.1:1/x", policy=lambda m, u: (False, "out of scope"))
    assert "out of scope" in str(exc.value)


def test_policy_denial_happens_before_playwright_import(monkeypatch):
    """Security property: the policy gate runs BEFORE the lazy Playwright import / any browser or
    network activity. If it did not, this would raise AssertionError (or RuntimeError), not
    PermissionError."""
    def _boom():
        raise AssertionError("playwright import reached despite a denying policy")

    monkeypatch.setattr(S, "_require_playwright", _boom)
    with pytest.raises(PermissionError):
        S.capture("http://127.0.0.1:1/x", policy=lambda m, u: (False, "blocked"))


def test_policy_receives_get_and_url():
    seen = {}

    def _pol(method, url):
        seen["method"] = method
        seen["url"] = url
        return False

    with pytest.raises(PermissionError):
        S.capture("http://example.test/path", policy=_pol)
    assert seen == {"method": "GET", "url": "http://example.test/path"}


def test_normalize_policy_styles():
    assert S._normalize_policy(True)[0] is True
    assert S._normalize_policy(False)[0] is False
    ok, reason = S._normalize_policy((False, "nope"))
    assert ok is False and reason == "nope"
    ok, reason = S._normalize_policy((True, ""))
    assert ok is True


# --------------------------------------------------------------------------- pure assembly helper

def test_build_result_shape_sha_and_timestamp():
    png = b"\x89PNG\r\n\x1a\n" + b"fake-image-bytes"
    res = S._build_result(
        png, path="relative/shot.png", requested_url="http://a/x", final_url="http://a/y",
        title="Proof", width=1440, height=900, full_page=True, element_selector=None,
        console=["log: hi"], status=200, error=None)

    # shape
    assert isinstance(res, S.ShotResult)
    assert res.requested_url == "http://a/x"
    assert res.url == "http://a/y"
    assert res.title == "Proof"
    assert res.width == 1440 and res.height == 900
    assert res.full_page is True
    assert res.element_selector is None
    assert res.console == ["log: hi"]
    assert res.status == 200
    assert res.error is None

    # evidence chain: sha256 of the EXACT bytes + absolute path
    assert res.sha256 == hashlib.sha256(png).hexdigest()
    assert os.path.isabs(res.path)

    # captured_at is ISO8601 UTC
    parsed = datetime.fromisoformat(res.captured_at)
    assert parsed.utcoffset() is not None
    assert parsed.utcoffset().total_seconds() == 0


def test_build_result_defaults():
    res = S._build_result(b"x", path="/tmp/x.png", requested_url="u", final_url="u",
                          title="", width=1, height=1, full_page=False, element_selector="#id")
    assert res.console == []
    assert res.status is None
    assert res.error is None
    assert res.element_selector == "#id"


def test_default_out_path_under_tempdir():
    import tempfile
    p = S._default_out_path()
    assert p.endswith(".png")
    assert os.path.isdir(os.path.dirname(p))
    assert tempfile.gettempdir() in p


# --------------------------------------------------------------------------- loopback smoke test

@requires_playwright
def test_loopback_capture(tmp_path):
    html = b"<!doctype html><html><head><title>Evidence OK</title></head>" \
           b"<body><h1>stored-xss-proof</h1></body></html>"

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        def log_message(self, *a):  # silence
            pass

    with socketserver.TCPServer(("127.0.0.1", 0), _Handler) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            out = str(tmp_path / "shot.png")
            res = S.capture(f"http://127.0.0.1:{port}/", out_path=out, timeout=15.0)
        finally:
            srv.shutdown()

    assert os.path.exists(res.path)
    assert os.path.getsize(res.path) > 0
    assert res.title == "Evidence OK"
    assert res.status == 200
    assert res.sha256 == hashlib.sha256(open(res.path, "rb").read()).hexdigest()
    # PNG magic bytes
    with open(res.path, "rb") as fh:
        assert fh.read(8) == b"\x89PNG\r\n\x1a\n"
