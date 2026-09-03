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
    from collections import defaultdict, deque
    urls = [u for u in seed_urls if (has_params(u) if require_params else True)]
    # Dedup to distinct ENDPOINTS (path + sorted param NAMES), not raw strings: a crawl yields many
    # query-VALUE variants of one injection point, which otherwise crowd the list (and the cap) with
    # duplicates of the same endpoint and starve others.
    byep = {}
    for u in urls:
        p = urlsplit(u)
        names = tuple(sorted(kv.split("=")[0] for kv in p.query.split("&") if kv))
        byep.setdefault((p.path, names), u)
    endpoints = list(byep.values())
    if cap and len(endpoints) > cap:
        # Stratify the cap across the first path segment so one directory (/hackable, /login, ...)
        # cannot consume the whole budget and starve real injection points in another
        # (/vulnerabilities/...). Round-robin across groups instead of an alphabetical head-slice
        # (which silently dropped every late-sorting endpoint, e.g. /vulnerabilities/sqli).
        groups = defaultdict(deque)
        for u in sorted(endpoints):
            seg = urlsplit(u).path.strip("/").split("/")[0]
            groups[seg].append(u)
        picked, queues = [], list(groups.values())
        while len(picked) < cap and any(queues):
            for q in queues:
                if q:
                    picked.append(q.popleft())
                    if len(picked) >= cap:
                        break
        if log:
            log(f"COVERAGE CAP: {cap} of {len(endpoints)} injection endpoints "
                f"(stratified across {len(groups)} path groups; {len(endpoints) - cap} dropped)")
        return picked
    return sorted(endpoints)
