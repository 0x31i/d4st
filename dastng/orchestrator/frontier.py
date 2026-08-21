"""Shared URL/param frontier with a capped convergence loop.

Every discovery tool (katana, ZAP, DOMDig, x8, ffuf, gau) feeds its findings into the
frontier; the scanners re-consume it. New discoveries reopen the frontier for another
round, up to max_rounds. Coverage caps are recorded and surfaced, never silently applied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit, urlunsplit


def normalize_url(raw: str) -> str:
    """Canonicalize a URL for dedup: lowercase scheme/host, strip fragment, drop query
    VALUES but keep the set of param names (values vary per-scan and would defeat dedup).
    """
    raw = (raw or "").strip()
    if not raw:
        return ""
    parts = urlsplit(raw)
    scheme = (parts.scheme or "http").lower()
    netloc = parts.netloc.lower()
    path = parts.path or "/"
    params = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    query = "&".join(params)  # names only, sorted
    return urlunsplit((scheme, netloc, path, query, ""))


@dataclass
class Frontier:
    max_rounds: int = 3
    _urls: set[str] = field(default_factory=set)
    _params: set[tuple[str, str]] = field(default_factory=set)  # (normalized_url, param)
    _round: int = 0
    _new_since_consume: bool = False
    caps: list[str] = field(default_factory=list)

    def add_url(self, url: str) -> bool:
        key = normalize_url(url)
        if not key or key in self._urls:
            return False
        self._urls.add(key)
        self._new_since_consume = True
        for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            self._params.add((key, k))
        return True

    def add_param(self, url: str, param: str) -> bool:
        key = (normalize_url(url), param)
        if key in self._params:
            return False
        self._params.add(key)
        self._new_since_consume = True
        return True

    def add_urls(self, urls) -> int:
        return sum(1 for u in urls if self.add_url(u))

    def urls(self) -> list[str]:
        return sorted(self._urls)

    def params(self) -> list[tuple[str, str]]:
        return sorted(self._params)

    def should_continue(self) -> bool:
        """True if there is new surface to scan and we are under the round cap.

        Records a coverage cap (surfaced to the operator) when we stop with new surface
        still pending because the round limit was hit.
        """
        if not self._new_since_consume:
            return False
        if self._round >= self.max_rounds:
            self.caps.append(
                f"round cap {self.max_rounds} reached with new surface still pending "
                f"({len(self._urls)} urls, {len(self._params)} params)"
            )
            return False
        return True

    def begin_round(self) -> int:
        self._round += 1
        self._new_since_consume = False
        return self._round

    def stats(self) -> dict:
        return {
            "urls": len(self._urls),
            "params": len(self._params),
            "rounds": self._round,
            "caps": list(self.caps),
        }
