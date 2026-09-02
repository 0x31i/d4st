"""Helpers for turning the shared frontier into per-tool target lists.

Injection tools (sqlmap, dalfox, commix) want URLs that carry parameters (injection points).
This picks those candidates and applies an explicit, LOGGED cap so we never silently drop
surface (a standing project rule).
"""

from __future__ import annotations

from urllib.parse import urlsplit


def has_params(url: str) -> bool:
    return bool(urlsplit(url).query)


def candidate_urls(seed_urls, *, require_params: bool = True, cap: int = 0,
                   log=None) -> list[str]:
    """Select target URLs for an injection tool.

    require_params: keep only URLs with a query string (injectable points).
    cap: 0 = no cap; >0 = keep at most `cap`, and log what was dropped.
    """
    urls = [u for u in seed_urls if (has_params(u) if require_params else True)]
    # stable order for reproducibility
    urls = sorted(dict.fromkeys(urls))
    if cap and len(urls) > cap:
        dropped = len(urls) - cap
        if log:
            log(f"COVERAGE CAP: capped injection targets to {cap} of {len(urls)} "
                f"({dropped} dropped)")
        urls = urls[:cap]
    return urls
