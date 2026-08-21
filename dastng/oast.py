"""Out-of-band (OAST) callback server for blind-vuln detection.

RFI/SSRF/blind-XXE/blind-cmdi leave no in-band signal; the only proof is the target reaching
BACK to an attacker-controlled host. For real engagements the tool uses interactsh (public or
self-hosted, over the internet). For a LAN target (a self-hosted appliance scanning an app on
the same network, or the WAVSEP benchmark) a local callback server on a reachable interface is
simpler and needs no internet egress.

Each probe embeds a unique token in the callback path; a hit on that token proves the target
fetched attacker-controlled content. Used by the RFI adapter and available to nuclei via
DASTNG_INTERACTSH_SERVER for the real-engagement path.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# A token the included body carries, so an RFI that reflects the include is also caught in-band.
OAST_BODY_TOKEN = "DASTNG_OAST_9f3a2c"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _serve(self):
        self.server.hits.append(self.path)  # type: ignore[attr-defined]
        body = f"{OAST_BODY_TOKEN}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:  # noqa: BLE001,S110 - client hangup after callback logged is harmless
            pass

    def do_GET(self):
        self._serve()

    def do_POST(self):
        self._serve()


class OastServer:
    """Context-managed local callback server. `base(host_ip)` builds a probe URL carrying a
    unique token; `saw(token)` reports whether the target called back."""

    def __init__(self, bind: str = "0.0.0.0", port: int = 0):
        self.httpd = HTTPServer((bind, port), _Handler)
        self.httpd.hits = []  # type: ignore[attr-defined]
        self.port = self.httpd.server_address[1]

    @property
    def hits(self) -> list[str]:
        return self.httpd.hits  # type: ignore[attr-defined]

    def probe_url(self, host_ip: str, token: str) -> str:
        return f"http://{host_ip}:{self.port}/{token}"

    def saw(self, token: str) -> bool:
        return any(token in h for h in self.hits)

    def __enter__(self):
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
