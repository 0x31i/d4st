import threading

import pytest

from d4st.dom import _cookies_for


def test_cookies_parsed_for_playwright():
    cs = _cookies_for("security=low; PHPSESSID=abc123", "h.test")
    names = {c["name"]: c["value"] for c in cs}
    assert names == {"security": "low", "PHPSESSID": "abc123"}
    assert all(c["domain"] == "h.test" and c["path"] == "/" for c in cs)


def test_empty_cookie():
    assert _cookies_for("", "h.test") == []


def test_taint_harness_has_marker_and_sinks():
    from d4st.dom import _TAINT, _TAINT_HARNESS
    assert _TAINT in _TAINT_HARNESS
    for sink in ("document.cookie", "storage.setItem", "setAttribute", "innerHTML", "input.value"):
        assert sink in _TAINT_HARNESS


def _chromium_ok():
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            b.close()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _chromium_ok(), reason="playwright chromium not installed")
def test_dom_cookie_manipulation_via_window_name():
    """window.name (a non-URL source) read into document.cookie => dom-cookie-manipulation,
    and a clean page must yield nothing (no self-FP from our own source seeding)."""
    import http.server
    import socketserver

    from d4st.dom import dom_probe

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            if self.path.startswith("/vuln"):
                b = "<html><body><script>try{document.cookie='p='+window.name;}catch(e){}</script></body></html>"
            else:
                b = "<html><body><h1>clean</h1></body></html>"
            self.wfile.write(b.encode())

    srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        vuln = dom_probe(f"http://127.0.0.1:{port}/vuln", "", params=[])
        clean = dom_probe(f"http://127.0.0.1:{port}/clean", "", params=[])
    finally:
        srv.shutdown()

    assert any(f.category == "dom-cookie-manipulation" and f.source == "window.name" for f in vuln)
    assert clean == []
