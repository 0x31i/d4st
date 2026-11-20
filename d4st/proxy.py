"""Intercepting-proxy engine — capture / pause / modify / forward / replay live HTTP(S) traffic.

This is d4st's Burp-Proxy half: a headless `mitmproxy` `DumpMaster` running in the background with an
addon that records every flow, can pause ("intercept") flows matching a filter, and lets the operator
resume / drop / modify / replay them. Captured flows serialize to the same Burp-grade
`evidence.exchange` shape every other d4st module emits, so a paused or replayed request renders in the
console/report identically to a scan finding.

Public-tool posture (hard rule): this is a generic pentest proxy feature. It knows nothing about any
particular engagement or driver. The only extension seam is a neutral, pluggable `policy(method, url)`
hook — an outside caller can inject its own pre-send check without this module knowing what it is.

Safety model (two generic, built-in guards + the optional hook):
  1. Scope-lock      — a tool-initiated send whose host is not in `scope_hosts` is refused
                       (reuses `d4st.scope.in_scope`).
  2. Destructive-block — a DELETE verb or a destructive / session-destroying path is refused for
                       tool-initiated sends, exactly as `d4st.replay`/`d4st.sweep` refuse it (create ->
                       update only; delete stays a deliberate manual action — never auto-fired here).
  3. policy hook     — called before EVERY tool-initiated send, in addition to the two built-ins.

Observe vs. act: PASSIVE in-path capture of traffic the operator's own browser makes through the proxy
is observe-only — those requests are forwarded as the browser issued them and merely recorded; they are
NOT policy-gated (the operator, not the tool, initiated them). Only TOOL-initiated egress —
`modify_replay`, and a `resume` that changes method/url/body — is routed through the guards above.

`drop` reliability (mitmproxy issue #4711): `flow.kill()` cannot abort a flow already in transit, so
`drop` is guaranteed only on a flow PAUSED in an intercept (not yet forwarded). To reliably block an
outbound request, `set_intercept` a matching filter FIRST, then `drop` the paused flow — enforced below.

Runtime: the primary model is "single-loop cooperative" — `DumpMaster.run()` is a child asyncio task on
the caller's own loop, and every flow mutation runs on that loop (mitmproxy hooks and `Flow`'s internal
resume event live there). A synchronous caller (the CLI, tests) uses `BackgroundProxy`, the documented
"dedicated proxy-thread + run_coroutine_threadsafe" fallback, which owns a thread+loop and marshals each
mutation onto it.

mitmproxy requires Python >= 3.10; it is an optional extra (`pip install 'd4st[proxy]'`). The import is
deferred into `start()` so the rest of d4st keeps working on the 3.9 floor without it installed.
"""

from __future__ import annotations

import asyncio
import os
import socket
import threading
import time
import uuid
from typing import Any, Callable, Optional

from . import evidence
from .safety import is_session_destroying_endpoint, is_state_changing, is_auth_endpoint
from .scope import in_scope

# Verbs that never egress state. Everything else is "state-changing" for a tool-initiated send and
# needs explicit authorization; DELETE is refused outright (mirrors d4st.replay / d4st.sweep).
_READ_ONLY_VERBS = {"GET", "HEAD", "OPTIONS"}

Policy = Callable[[str, str], None]


# --------------------------------------------------------------------------------------------------
# Flow store — in-memory, stable IDs, FIFO eviction. (Pattern adapted MIT-clean from the public
# mitmproxy-addon idiom: dict keyed by mitmproxy's own per-flow UUID + ordered id list + a lock.)
# --------------------------------------------------------------------------------------------------
class FlowStore:
    """Thread-safe in-memory store of captured flows, keyed by mitmproxy's stable `flow.id`.

    `add` upserts, so the same flow id survives the request->response upsert (one stable id per
    exchange). `max_flows` evicts oldest-first. An optional `persist_path` tees every captured flow
    into a native mitmproxy `.flows` file (interchangeable with the mitmproxy CLI) via
    `mitmproxy.io.FlowWriter` — the public, format-stable persistence path; a richer SQLite index can
    layer on top of d4st's own store, left to the embedding driver.
    """

    def __init__(self, max_flows: int = 1000, persist_path: Optional[str] = None):
        self._flows: dict[str, Any] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self.max_flows = max_flows
        self._persist_path = persist_path
        self._writer = None
        self._writer_fh = None
        if persist_path:
            # Open lazily-safe; mitmproxy import happens in the engine, but FlowWriter is light.
            from mitmproxy.io import FlowWriter  # noqa: F401  (import-guarded by caller)
            self._writer_fh = open(persist_path, "wb")
            self._writer = FlowWriter(self._writer_fh)

    def add(self, flow: Any) -> None:
        with self._lock:
            fid = flow.id
            if fid not in self._flows:
                self._order.append(fid)
            self._flows[fid] = flow
            while len(self._order) > self.max_flows:
                old = self._order.pop(0)
                self._flows.pop(old, None)
        if self._writer is not None:
            try:
                self._writer.add(flow)
                self._writer_fh.flush()
            except Exception:  # noqa: BLE001 - persistence must never break live capture
                pass

    def get(self, flow_id: str) -> Any:
        with self._lock:
            return self._flows.get(flow_id)

    def get_all(self) -> list[Any]:
        with self._lock:
            return [self._flows[i] for i in self._order if i in self._flows]

    def remove(self, flow_id: str) -> None:
        with self._lock:
            self._flows.pop(flow_id, None)
            if flow_id in self._order:
                self._order.remove(flow_id)

    def clear(self) -> None:
        with self._lock:
            self._flows.clear()
            self._order.clear()

    def count(self) -> int:
        with self._lock:
            return len(self._order)

    def close(self) -> None:
        if self._writer_fh is not None:
            try:
                self._writer_fh.flush()
                self._writer_fh.close()
            except Exception:  # noqa: BLE001
                pass
            self._writer_fh = None
            self._writer = None


# --------------------------------------------------------------------------------------------------
# Addon — mitmproxy drives this; populates the store and pauses matching flows.
# --------------------------------------------------------------------------------------------------
class ProxyAddon:
    """mitmproxy addon: records every flow and intercepts (pauses) those matching the active filter.

    `request`/`response` are mitmproxy's public addon hook names. Interception is observe-and-hold:
    pausing a flow changes nothing outbound on its own — the operator decides resume/drop/modify.
    """

    def __init__(self, store: FlowStore):
        self.store = store
        self._filter = None          # parsed flowfilter, or None (disabled)
        self._intercepted: dict[str, Any] = {}

    def set_intercept(self, flt: str) -> None:
        from mitmproxy import flowfilter
        flt = (flt or "").strip()
        if not flt:
            self._filter = None
            return
        parsed = flowfilter.parse(flt)
        if parsed is None:
            raise ValueError(f"invalid intercept filter: {flt!r}")
        self._filter = parsed

    # --- mitmproxy hooks --------------------------------------------------------------------------
    def request(self, flow: Any) -> None:
        from mitmproxy import flowfilter
        self.store.add(flow)
        if self._filter is not None and flowfilter.match(self._filter, flow):
            flow.intercept()                 # pauses; the proxy internally awaits wait_for_resume()
            self._intercepted[flow.id] = flow

    def response(self, flow: Any) -> None:
        self.store.add(flow)                 # upsert: same id now carries the response
        self._intercepted.pop(flow.id, None)

    def error(self, flow: Any) -> None:
        self.store.add(flow)
        self._intercepted.pop(flow.id, None)

    def intercepted_flows(self) -> list[Any]:
        return [f for f in self._intercepted.values() if getattr(f, "intercepted", False)]

    def forget_intercept(self, flow_id: str) -> None:
        self._intercepted.pop(flow_id, None)


# --------------------------------------------------------------------------------------------------
# Serialization — flow -> d4st evidence.exchange shape + curl.
# --------------------------------------------------------------------------------------------------
def _text(message: Any) -> str:
    """Best-effort decoded body of a mitmproxy Request/Response (empty if none)."""
    if message is None:
        return ""
    try:
        return message.get_text(strict=False) or ""
    except Exception:  # noqa: BLE001
        try:
            return (message.raw_content or b"").decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return ""


def flow_to_exchange(flow: Any, label: str = "proxy capture") -> dict:
    """Serialize a captured flow to the canonical d4st evidence.exchange dict (headers redacted)."""
    req = getattr(flow, "request", None)
    resp = getattr(flow, "response", None)
    req_headers = dict(req.headers) if req is not None else {}
    resp_headers = dict(resp.headers) if resp is not None else {}
    ex = evidence.synthetic_exchange(
        label,
        method=getattr(req, "method", "GET") if req is not None else "GET",
        url=(req.pretty_url if req is not None else ""),
        req_headers=req_headers,
        req_body=_text(req),
        status=getattr(resp, "status_code", None) if resp is not None else None,
        resp_headers=resp_headers,
        resp_body=_text(resp),
    )
    # evidence.curl expects an httpx-ish object; build the repro directly from the flow instead.
    if req is not None:
        ex["repro"] = _flow_curl(req)
        ex["raw_request"] = evidence.raw_request(
            req.method, req.pretty_url, evidence.redact_headers(req_headers), _text(req))
    ex["id"] = flow.id
    ex["intercepted"] = bool(getattr(flow, "intercepted", False))
    return ex


def _flow_curl(req: Any) -> str:
    """copy-paste curl reproducing a captured mitmproxy request (auth redacted like evidence.curl)."""
    full = os.environ.get("D4ST_FULL_AUTH") == "1"
    parts = [f"curl -i -sk -X {req.method}"]
    skip = {"host", "content-length", "connection", "accept-encoding"}
    for k, v in dict(req.headers).items():
        if k.lower() in skip:
            continue
        if k.lower() == "authorization" and not full:
            v = str(v)[:26] + "…"
        parts.append(f"-H '{k}: {v}'")
    body = _text(req)
    if body:
        parts.append(f"--data '{body[:2000]}'")
    parts.append(f"'{req.pretty_url}'")
    return " ".join(parts)


def _flow_summary(flow: Any) -> dict:
    req = getattr(flow, "request", None)
    resp = getattr(flow, "response", None)
    return {
        "id": flow.id,
        "method": getattr(req, "method", None) if req is not None else None,
        "url": (req.pretty_url if req is not None else None),
        "host": (req.pretty_host if req is not None else None),
        "status": getattr(resp, "status_code", None) if resp is not None else None,
        "ts": getattr(req, "timestamp_start", None) if req is not None else None,
        "intercepted": bool(getattr(flow, "intercepted", False)),
    }


# --------------------------------------------------------------------------------------------------
# Engine — async-native (single-loop cooperative model).
# --------------------------------------------------------------------------------------------------
class ProxyEngine:
    """Headless intercepting proxy. Observe methods are plain (store reads); flow-mutating / egress
    methods are coroutines that must run on the engine's loop (the single-loop contract).

    A synchronous caller should use `BackgroundProxy`, which owns the loop in a thread and marshals.
    """

    def __init__(self, policy: Optional[Policy] = None, scope_hosts: Optional[list[str]] = None,
                 listen_host: str = "127.0.0.1", listen_port: int = 8080,
                 store: Optional[FlowStore] = None, max_flows: int = 1000,
                 ssl_insecure: bool = True, persist_path: Optional[str] = None):
        self.policy = policy
        self.scope_hosts = list(scope_hosts or [])
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.ssl_insecure = ssl_insecure
        self.store = store or FlowStore(max_flows=max_flows, persist_path=persist_path)
        self.addon: Optional[ProxyAddon] = None
        self.master = None
        self._task: Optional[asyncio.Task] = None

    # --- lifecycle --------------------------------------------------------------------------------
    async def start(self) -> dict:
        """Build options + DumpMaster, install the addon, and run it as a child task on this loop."""
        from mitmproxy.options import Options
        from mitmproxy.tools.dump import DumpMaster

        opts = Options(listen_host=self.listen_host, listen_port=self.listen_port,
                       ssl_insecure=self.ssl_insecure)
        self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self.addon = ProxyAddon(self.store)
        self.master.addons.add(self.addon)
        self._task = asyncio.create_task(self.master.run())
        await self._await_listening()
        return {"listen": f"{self.listen_host}:{self.listen_port}", "ca": ca_cert_path()}

    async def _await_listening(self, timeout: float = 10.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._task is not None and self._task.done():
                # surface a bind failure instead of hanging
                self._task.result()
            try:
                with socket.create_connection((self.listen_host, self.listen_port), timeout=0.25):
                    return
            except OSError:
                await asyncio.sleep(0.1)
        raise TimeoutError(f"proxy did not start listening on {self.listen_host}:{self.listen_port}")

    async def stop(self) -> None:
        if self.master is not None:
            self.master.shutdown()
        if self._task is not None:
            try:
                await self._task
            except Exception:  # noqa: BLE001
                pass
        self.store.close()

    # --- observe (no egress, never policy-checked) ------------------------------------------------
    def list_flows(self, flt: Optional[dict] = None) -> list[dict]:
        """Newest-first flow summaries. `flt` keys: method, url_re, status, host, intercepted."""
        import re
        rows = [_flow_summary(f) for f in self.store.get_all()]
        rows.reverse()
        if not flt:
            return rows
        out = []
        url_re = re.compile(flt["url_re"]) if flt.get("url_re") else None
        for r in rows:
            if flt.get("method") and (r["method"] or "").upper() != flt["method"].upper():
                continue
            if flt.get("host") and (r["host"] or "") != flt["host"]:
                continue
            if flt.get("status") is not None and r["status"] != flt["status"]:
                continue
            if flt.get("intercepted") is not None and r["intercepted"] != bool(flt["intercepted"]):
                continue
            if url_re is not None and not url_re.search(r["url"] or ""):
                continue
            out.append(r)
        return out

    def get_flow(self, flow_id: str) -> dict:
        flow = self.store.get(flow_id)
        if flow is None:
            raise KeyError(f"no such flow: {flow_id}")
        return flow_to_exchange(flow, label=f"proxy capture {flow_id}")

    def to_flow_dict(self, flow_id: str) -> dict:
        """Serialize a captured request to {method,url,headers,body} for handing to another tool."""
        flow = self.store.get(flow_id)
        if flow is None:
            raise KeyError(f"no such flow: {flow_id}")
        req = flow.request
        return {"method": req.method, "url": req.pretty_url,
                "headers": dict(req.headers), "body": _text(req)}

    def set_intercept(self, flt: str) -> None:
        if self.addon is None:
            raise RuntimeError("proxy not started")
        self.addon.set_intercept(flt)

    def intercepted(self) -> list[dict]:
        if self.addon is None:
            return []
        return [_flow_summary(f) for f in self.addon.intercepted_flows()]

    # --- the guard chain (every TOOL-initiated send goes through here) ----------------------------
    def _check_send(self, method: str, url: str, manual_destructive: bool = False) -> None:
        m = (method or "GET").upper()
        # 1. scope-lock
        if not in_scope(url, self.scope_hosts):
            raise ValueError(f"{url} is out of scope (scope_hosts={self.scope_hosts or 'unset'})")
        # 2. destructive-block (identical posture to d4st.replay / d4st.sweep)
        if m == "DELETE" or is_session_destroying_endpoint(url):
            raise ValueError(
                f"{m} {url} is refused outright: DELETE / session-destroying requests are never "
                "auto-fired by a d4st primitive; manual_destructive cannot authorize it")
        if not manual_destructive and (m not in _READ_ONLY_VERBS
                                       or is_state_changing(url) or is_auth_endpoint(url)):
            raise ValueError(
                f"{m} {url} is not read-only (write verb or destructive/auth path); "
                "pass manual_destructive=True to authorize it")
        # 3. pluggable policy hook — d4st attaches no meaning to it
        if self.policy is not None:
            self.policy(m, url)

    # --- act (flow mutation / egress — run on the engine loop) ------------------------------------
    async def resume(self, flow_id: str, modified: Optional[dict] = None) -> dict:
        """Resume a paused flow. If `modified` changes method/url/body, it is a tool-initiated egress
        and is guarded; a plain resume (forward the browser's own request unchanged) is not."""
        flow = self.store.get(flow_id)
        if flow is None or not getattr(flow, "intercepted", False):
            raise KeyError(f"no intercepted flow: {flow_id}")
        if modified:
            req = flow.request
            new_method = modified.get("method", req.method)
            new_url = modified.get("url", req.pretty_url)
            changes_egress = (
                ("method" in modified and modified["method"].upper() != req.method.upper())
                or ("url" in modified and modified["url"] != req.pretty_url)
                or ("body" in modified)
            )
            if changes_egress:
                self._check_send(new_method, new_url, modified.get("manual_destructive", False))
            if "method" in modified:
                req.method = modified["method"].upper()
            if "url" in modified:
                req.url = modified["url"]
            for k, v in (modified.get("headers") or {}).items():
                req.headers[k] = v
            for k in (modified.get("remove_headers") or []):
                if k in req.headers:
                    del req.headers[k]
            if "body" in modified:
                req.text = modified["body"]
        flow.resume()
        if self.addon is not None:
            self.addon.forget_intercept(flow_id)
        return {"ok": True, "id": flow_id, "modified": bool(modified)}

    async def drop(self, flow_id: str) -> dict:
        """Kill a flow. RELIABLE ONLY on a PAUSED/intercepted flow (mitmproxy #4711: a flow already in
        transit cannot be killed). We enforce intercept-then-drop: refuse to 'drop' a flow that is not
        currently paused, so a caller never believes it blocked a request it did not."""
        flow = self.store.get(flow_id)
        if flow is None:
            raise KeyError(f"no such flow: {flow_id}")
        if not getattr(flow, "intercepted", False):
            raise ValueError(
                f"{flow_id} is not paused: drop is reliable only on an intercepted (paused) flow "
                "(mitmproxy #4711 cannot kill a flow in transit). set_intercept a matching filter "
                "BEFORE the request, then drop the paused flow.")
        if not getattr(flow, "killable", False):
            raise ValueError(f"{flow_id} is not killable")
        flow.kill()
        if self.addon is not None:
            self.addon.forget_intercept(flow_id)
        return {"ok": True, "id": flow_id, "killed": True}

    async def modify_replay(self, flow_id: str, changes: Optional[dict] = None,
                            manual_destructive: bool = False, timeout: float = 20.0) -> dict:
        """Clone a captured flow, apply `changes`, run it through the guard chain, then replay it
        THROUGH the proxy via the `replay.client` command and poll for the response. Tool-initiated,
        so always guarded."""
        if self.master is None:
            raise RuntimeError("proxy not started")
        src = self.store.get(flow_id)
        if src is None:
            raise KeyError(f"no such flow: {flow_id}")
        clone = src.copy()                               # new flow.id, detached copy
        req = clone.request
        changes = changes or {}
        if "method" in changes:
            req.method = changes["method"].upper()
        if "url" in changes:
            req.url = changes["url"]
        for k, v in (changes.get("headers") or {}).items():
            req.headers[k] = v
        for k in (changes.get("remove_headers") or []):
            if k in req.headers:
                del req.headers[k]
        if "body" in changes:
            req.text = changes["body"]
        clone.response = None                            # force a fresh send
        self._check_send(req.method, req.pretty_url, manual_destructive)
        self.store.add(clone)
        self.master.commands.call("replay.client", [clone])
        deadline = time.time() + timeout
        while time.time() < deadline:
            if clone.response is not None or getattr(clone, "error", None) is not None:
                break
            await asyncio.sleep(0.05)
        if getattr(clone, "error", None) is not None:
            return {"ok": False, "id": clone.id, "error": str(clone.error)}
        return {"ok": True, "id": clone.id,
                "exchange": flow_to_exchange(clone, label=f"replay {clone.id}")}

    def send_to_repeater(self, flow_id: str, *, send: bool = False,
                         manual_destructive: bool = False, **replay_kwargs) -> dict:
        """Hand a captured request to the d4st Repeater (`d4st.replay.replay`). By default this just
        serializes the request (a pure handoff); with `send=True` it fires it through the Repeater,
        which applies its OWN read-only / destructive guards and the same `policy` hook on the send."""
        spec = self.to_flow_dict(flow_id)
        if not send:
            return {"ok": True, "handoff": spec}
        from .replay import replay
        return replay(spec["method"], spec["url"], headers=spec["headers"], body=spec["body"],
                      allow_state_changing=manual_destructive, policy=self.policy, **replay_kwargs)

    # --- CA helpers -------------------------------------------------------------------------------
    def export_ca(self, dest: Optional[str] = None) -> str:
        return export_ca(dest)


# --------------------------------------------------------------------------------------------------
# CA trust (one documented manual operator step)
# --------------------------------------------------------------------------------------------------
def ca_cert_path() -> str:
    """Path to mitmproxy's generated CA cert (created on first proxy run at ~/.mitmproxy/)."""
    return os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")


def export_ca(dest: Optional[str] = None) -> str:
    """Copy the mitmproxy CA cert to `dest` (or return its path). The target browser must trust it
    ONCE before it can proxy HTTPS. This installs nothing — trusting a root CA is privileged and stays
    a deliberate manual step. On macOS:

        security add-trusted-cert -d -r trustRoot \\
            -k ~/Library/Keychains/login.keychain-db ~/.mitmproxy/mitmproxy-ca-cert.pem

    While proxying, mitmproxy also serves the cert at http://mitm.it for the browser to download.
    """
    src = ca_cert_path()
    if not os.path.exists(src):
        raise FileNotFoundError(
            f"{src} not found — it is generated on the first proxy run. Start the proxy once "
            "(d4st proxy start) to create it, then export.")
    if not dest:
        return src
    import shutil
    shutil.copyfile(src, dest)
    return dest


_MACOS_CA_HINT = (
    "macOS one-time trust step (operator-run, not auto-executed):\n"
    "  security add-trusted-cert -d -r trustRoot "
    "-k ~/Library/Keychains/login.keychain-db ~/.mitmproxy/mitmproxy-ca-cert.pem\n"
    "or visit http://mitm.it while the browser is pointed at the proxy.")


# --------------------------------------------------------------------------------------------------
# BackgroundProxy — the documented thread + run_coroutine_threadsafe fallback for synchronous callers
# (the CLI and tests). Owns a dedicated asyncio loop in a daemon thread and marshals every mutation
# onto it; observe methods read the thread-safe store directly.
# --------------------------------------------------------------------------------------------------
class BackgroundProxy:
    """Run a `ProxyEngine` on its own loop in a background thread, exposing a synchronous API."""

    def __init__(self, **engine_kwargs):
        self.engine = ProxyEngine(**engine_kwargs)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _submit(self, coro):
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result()

    def start(self) -> dict:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, name="d4st-proxy", daemon=True)
        self._thread.start()
        return self._submit(self.engine.start())

    def stop(self) -> None:
        if self._loop is None:
            return
        try:
            self._submit(self.engine.stop())
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            if self._thread is not None:
                self._thread.join(timeout=5)

    # observe — direct (thread-safe reads)
    def list_flows(self, flt=None):
        return self.engine.list_flows(flt)

    def get_flow(self, flow_id):
        return self.engine.get_flow(flow_id)

    def to_flow_dict(self, flow_id):
        return self.engine.to_flow_dict(flow_id)

    def set_intercept(self, flt):
        return self.engine.set_intercept(flt)

    def intercepted(self):
        return self.engine.intercepted()

    def send_to_repeater(self, flow_id, **kw):
        return self.engine.send_to_repeater(flow_id, **kw)

    def export_ca(self, dest=None):
        return self.engine.export_ca(dest)

    # act — marshalled onto the engine loop
    def resume(self, flow_id, modified=None):
        return self._submit(self.engine.resume(flow_id, modified))

    def drop(self, flow_id):
        return self._submit(self.engine.drop(flow_id))

    def modify_replay(self, flow_id, changes=None, manual_destructive=False):
        return self._submit(self.engine.modify_replay(flow_id, changes, manual_destructive))
