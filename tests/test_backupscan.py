"""Backup/temp file exposure detector — true-positive + catch-all FP guard."""
import http.server
import socketserver
import threading

import pytest

from d4st.activetests import run_backup_scan

httpx = pytest.importorskip("httpx")


def _make_handler(catchall: bool):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if catchall:
                # every path returns the SAME 200 shell (OWA-style soft-404) — the FP trap
                self._send(200, "<html>CATCHALL APP SHELL always 200</html>")
                return
            if self.path == "/app.js":
                self._send(200, "console.log('app');")
            elif self.path == "/app.js.bak":
                self._send(200, "DB_PASSWORD=hunter2  // leaked source backup")
            else:
                self._send(404, "not found")

        def _send(self, code, body):
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body.encode())

    return _H


class _Session:
    headers: dict = {}

    def cookie_header(self, base):
        return ""


def _serve(catchall):
    srv = socketserver.TCPServer(("127.0.0.1", 0), _make_handler(catchall))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_backup_true_positive():
    srv = _serve(catchall=False)
    port = srv.server_address[1]
    try:
        base = f"http://127.0.0.1:{port}/"
        out = run_backup_scan(_Session(), base, [f"http://127.0.0.1:{port}/app.js"])
        assert len(out) == 1
        assert out[0]["type"] == "backup-file-exposure"
        assert out[0]["url"].endswith("/app.js.bak")
    finally:
        srv.shutdown()


def test_backup_no_fp_on_catchall():
    srv = _serve(catchall=True)
    port = srv.server_address[1]
    try:
        base = f"http://127.0.0.1:{port}/"
        out = run_backup_scan(_Session(), base, [f"http://127.0.0.1:{port}/app.js"])
        assert out == [], "catch-all server must not yield phantom backup findings"
    finally:
        srv.shutdown()
