"""SignalR / WebSocket testing — the realtime-channel depth no generic crawler or Burp active scan
reaches. A .NET chat feature (e.g. a ChatRoom hub) almost certainly runs on SignalR over WebSocket; the
HTTP crawl never negotiates the hub, so the whole channel goes untested.

What it does (read-only, throttled):
  1. discover the SignalR/WS surface — negotiate endpoints from the harvested URLs + JS bundle refs
     + a small set of conventional .NET paths (/chathub/negotiate, /hubs/*/negotiate, /signalr/…).
  2. broken-auth on the realtime channel — the SignalR `negotiate` handshake returns a
     connectionToken/connectionId; if it succeeds WITHOUT the bearer, the realtime channel is
     unauthenticated (same class as the /api/ChatRoom unauth leak, but on the socket).
  3. WS message probe (optional) — if `websocket-client` is installed, upgrade the connection and
     record the server's handshake/first frames as proof. Message injection stays read-only.

The `negotiate` handshake is metadata-only (no chat message is sent), so this does not post content
to the channel. Every finding carries full evidence + repro.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urljoin

from .evidence import curl, exchange, synthetic_exchange

# JS/URL hints that a SignalR hub exists
_HUB_HINT = re.compile(r"""["'/]([A-Za-z0-9_\-/]*?(?:hub|signalr|chat|notif|realtime)[A-Za-z0-9_\-/]*)["'/]?""",
                       re.IGNORECASE)
_CONN_MARKER = re.compile(r'"(connectionToken|connectionId|availableTransports|negotiateVersion)"',
                          re.IGNORECASE)
_CONVENTIONAL = [
    "/chathub/negotiate", "/chatHub/negotiate", "/hubs/chat/negotiate", "/hub/negotiate",
    "/signalr/negotiate", "/notificationhub/negotiate", "/hubs/notification/negotiate",
    "/messagehub/negotiate", "/api/chathub/negotiate",
]


def _authed_headers(session, base: str) -> dict:
    h = dict(getattr(session, "headers", {}) or {})
    try:
        ck = session.cookie_header(base)
        if ck:
            h["Cookie"] = ck
    except Exception:  # noqa: BLE001
        pass
    return h


def _discover(urls: list[str], js_dir: str | None, origin: str) -> list[str]:
    """Collect candidate negotiate URLs from harvested URLs, JS bodies, and conventions."""
    cands: set[str] = set()
    for u in urls or []:
        low = u.lower()
        if "negotiate" in low or "/hub" in low or "signalr" in low:
            # normalise to a negotiate endpoint
            if "negotiate" in low:
                cands.add(u.split("?")[0])
            else:
                cands.add(u.split("?")[0].rstrip("/") + "/negotiate")
    # mine JS bodies for hub path hints
    if js_dir:
        import os
        for root, _dirs, files in os.walk(js_dir):
            for fn in files:
                if not fn.endswith(".js"):
                    continue
                try:
                    with open(os.path.join(root, fn), encoding="utf-8", errors="ignore") as fh:
                        txt = fh.read()
                except Exception:  # noqa: BLE001
                    continue
                for m in _HUB_HINT.finditer(txt):
                    path = m.group(1)
                    if not path or len(path) < 3 or path.startswith("http"):
                        continue
                    if any(x in path.lower() for x in ("hub", "signalr")):
                        p = "/" + path.strip("/")
                        cands.add(urljoin(origin, p.rstrip("/") + "/negotiate"))
    for p in _CONVENTIONAL:
        cands.add(urljoin(origin, p))
    return sorted(cands)


def run_ws_tests(session, base: str, urls: list[str], *, js_dir: str | None = None,
                 delay: float = 0.25, timeout: float = 12.0, max_cands: int = 30,
                 throttle=None) -> list[dict]:
    import httpx

    from .safety import pace

    origin = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"
    cands = _discover(urls, js_dir, origin)[:max_cands]
    if not cands:
        return []
    authed = _authed_headers(session, base)
    noauth = {k: v for k, v in authed.items() if k.lower() not in ("authorization", "cookie")}
    findings: list[dict] = []
    live_hubs: list[str] = []

    with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as c:
        for neg in cands:
            # SignalR negotiate is a POST that returns connection metadata (no message is sent).
            try:
                a = c.post(neg, headers=authed, content=b""); pace(throttle, delay, a.status_code)
            except Exception:  # noqa: BLE001
                continue
            authed_ok = a.status_code == 200 and _CONN_MARKER.search(a.text or "")
            if not authed_ok:
                # some hubs 404 on POST but 200 on GET negotiate (older SignalR)
                try:
                    a = c.get(neg, headers=authed); pace(throttle, delay, a.status_code)
                except Exception:  # noqa: BLE001
                    continue
                authed_ok = a.status_code == 200 and _CONN_MARKER.search(a.text or "")
            if not authed_ok:
                continue
            live_hubs.append(neg)

            # broken-auth on the realtime channel: negotiate WITHOUT the bearer
            try:
                n = c.request(a.request.method, neg, headers=noauth,
                              content=b"" if a.request.method == "POST" else None)
                pace(throttle, delay, n.status_code)
            except Exception:  # noqa: BLE001
                n = None
            if n is not None and n.status_code == 200 and _CONN_MARKER.search(n.text or ""):
                findings.append({
                    "type": "broken-auth-websocket", "name": "broken-auth-websocket",
                    "severity": "high", "url": neg, "method": a.request.method,
                    "category": "broken-auth", "verified": True,
                    "detail": f"the SignalR/WebSocket negotiate handshake at {neg} succeeds WITHOUT "
                              f"authentication (returned a connection token/transport list, status "
                              f"{n.status_code}). The realtime channel does not require the bearer, so "
                              f"an unauthenticated client can open the socket and receive/send hub "
                              f"messages — the socket-level analog of the /api/ChatRoom unauth leak.",
                    "evidence_log": [
                        exchange("Authenticated negotiate (baseline)", a),
                        exchange("PROOF — negotiate with the bearer REMOVED (still returns a "
                                 "connection token)", n)],
                    "repro": curl(n),
                })
            else:
                findings.append({
                    "type": "websocket-hub-exposed", "name": "websocket-hub-exposed",
                    "severity": "info", "url": neg, "method": a.request.method,
                    "category": "misconfiguration", "verified": True,
                    "detail": f"a SignalR/WebSocket hub is reachable at {neg} (authenticated negotiate "
                              f"returned a connection token). Auth is enforced on negotiate. Recorded "
                              f"for completeness; the live socket may warrant manual message-flow review.",
                    "evidence_log": [exchange("Authenticated negotiate — hub present", a)],
                    "repro": curl(a),
                })

        # optional live WS upgrade proof (only if websocket-client is available)
        if live_hubs:
            _ws_probe(live_hubs[0], authed, findings, timeout)
    return findings


def _ws_probe(neg_url: str, authed: dict, findings: list, timeout: float) -> None:
    """Best-effort: upgrade to the WS and capture the server's opening frame as proof. Uses
    websocket-client if installed; otherwise records that a live probe needs the library."""
    ws_url = neg_url.replace("/negotiate", "").replace("https://", "wss://").replace("http://", "ws://")
    try:
        import websocket  # type: ignore  (websocket-client)
    except Exception:  # noqa: BLE001
        findings.append({
            "type": "websocket-hub-exposed", "name": "websocket-probe-note", "severity": "info",
            "url": ws_url, "method": "GET", "category": "misconfiguration", "verified": False,
            "detail": "a live WebSocket message probe was skipped (install 'websocket-client' in the "
                      "appliance to capture opening frames). The negotiate-level findings above still "
                      "stand.",
            "evidence_log": [synthetic_exchange("WS upgrade (skipped — lib absent)", method="GET",
                                                url=ws_url, resp_body="websocket-client not installed")],
            "repro": f"# pip install websocket-client, then: wscat -c '{ws_url}'",
        })
        return
    try:
        hdr = [f"{k}: {v}" for k, v in authed.items() if k.lower() in ("authorization", "cookie")]
        ws = websocket.create_connection(ws_url, header=hdr, timeout=timeout,
                                         sslopt={"cert_reqs": 0})
        # SignalR handshake frame (JSON protocol) — read-only handshake, no chat content
        ws.send('{"protocol":"json","version":1}\x1e')
        frame = ws.recv()
        ws.close()
        findings.append({
            "type": "websocket-hub-exposed", "name": "websocket-live-frame", "severity": "info",
            "url": ws_url, "method": "GET", "category": "misconfiguration", "verified": True,
            "detail": f"live WebSocket upgrade to {ws_url} succeeded; server returned an opening frame.",
            "evidence_log": [synthetic_exchange("WS handshake frame", method="GET", url=ws_url,
                                                status=101, resp_body=str(frame)[:800])],
            "repro": f"wscat -c '{ws_url}'  # then send: {{\"protocol\":\"json\",\"version\":1}}",
        })
    except Exception as e:  # noqa: BLE001
        findings.append({
            "type": "websocket-hub-exposed", "name": "websocket-probe-note", "severity": "info",
            "url": ws_url, "method": "GET", "category": "misconfiguration", "verified": False,
            "detail": f"WS upgrade probe to {ws_url} did not complete ({e}). Negotiate-level findings stand.",
            "evidence_log": [synthetic_exchange("WS upgrade attempt", method="GET", url=ws_url,
                                                resp_body=str(e)[:400])],
            "repro": f"wscat -c '{ws_url}'",
        })
