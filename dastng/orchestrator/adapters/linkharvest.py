"""Deterministic link-harvester (crawl/discovery).

The blind WAVSEP benchmark showed katana reaching only 175 of 408 GET-reachable LFI cases:
on a dense index page it silently drops ~40% of the href links (its dedup/scope heuristics).
Crawl-reach, not detection, became the bottleneck. This adapter is a deterministic breadth-
first href harvester: it fetches each discovered page, extracts EVERY same-host link, and
re-seeds from index/listing pages for a bounded number of rounds. It complements katana
(which is JS-aware but heuristic) with exhaustive link-following on server-rendered listings,
which is exactly where recall leaks on real apps too (paginated tables, index pages).

Safety: same-host only, logout/auth endpoints skipped (never crawl a logout link -> kills the
session), bounded rounds + a hard page cap so it always terminates.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

import httpx

from ...safety import is_auth_endpoint
from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header

_HREF = re.compile(r'(?:href|src|action)=["\']([^"\']+)["\']', re.IGNORECASE)
# Pages worth re-seeding from (listing/index pages that fan out to many leaves).
_LISTING = re.compile(r'index[-.]|/index\.|list|catalog|category', re.IGNORECASE)


@register
class LinkHarvestAdapter(ToolAdapter):
    name = "linkharvest"
    stage = "crawl"
    discovers = True
    detects = False
    active = False
    binary = None  # pure-python (httpx)

    def run(self, ctx: RunContext) -> AdapterResult:
        host = urlsplit(ctx.target).hostname
        rounds = int(ctx.options.get("harvest_rounds", 3))
        page_cap = int(ctx.options.get("harvest_page_cap", 3000))
        timeout = ctx.options.get("http_timeout", 20)
        cmd = f"linkharvest host={host} rounds={rounds} cap={page_cap}"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")

        cookie = _cookie_header(ctx.session, ctx.target)
        headers = {"Cookie": cookie} if cookie else {}
        seeds = list(dict.fromkeys([ctx.target, *(ctx.seed_urls or [])]))
        seen: set[str] = set(seeds)
        frontier: set[str] = set()
        queue = [s for s in seeds if not is_auth_endpoint(s)]
        fetched = 0

        try:
            client = httpx.Client(follow_redirects=True, timeout=timeout, headers=headers)
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"client error: {exc}")

        with client:
            for _ in range(rounds):
                nxt: list[str] = []
                for url in queue:
                    if fetched >= page_cap:
                        break
                    fetched += 1
                    try:
                        body = client.get(url).text
                    except Exception:  # noqa: BLE001,S112 - one bad page must not sink discovery
                        continue
                    for raw in _HREF.findall(body):
                        link = urljoin(url, raw)
                        if urlsplit(link).hostname != host:
                            continue
                        link = link.split("#")[0]
                        if link in seen or is_auth_endpoint(link):
                            continue
                        seen.add(link)
                        if urlsplit(link).query:
                            frontier.add(link)
                        if _LISTING.search(link):
                            nxt.append(link)
                queue = nxt
                if not queue or fetched >= page_cap:
                    break

        capped = " (page cap hit)" if fetched >= page_cap else ""
        return AdapterResult(
            tool=self.name, ok=True, discovered_urls=sorted(frontier), command=cmd,
            note=f"{len(frontier)} param URLs from {fetched} pages{capped}",
        )
