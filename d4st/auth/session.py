"""Captured session model.

Wraps a Playwright storageState (cookies + per-origin localStorage/sessionStorage) plus any
extra headers (bearer token, custom auth header) and metadata (e.g. DVWA security level).
Serializes to a single JSON file under sessions/.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit


def _host(url: str) -> str:
    return urlsplit(url).hostname or ""


@dataclass
class Session:
    name: str
    origin: str = ""                       # base URL the session was captured against
    storage_state: dict = field(default_factory=dict)  # raw Playwright storageState (cookies + localStorage)
    headers: dict = field(default_factory=dict)         # extra headers to inject (e.g. Authorization: Bearer)
    session_storage: dict = field(default_factory=dict) # sessionStorage {k:v} — storage_state OMITS this
    meta: dict = field(default_factory=dict)            # arbitrary (security level, profile, ...)
    captured_at: str = ""

    def __post_init__(self) -> None:
        if not self.captured_at:
            self.captured_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # ----- cookies -----------------------------------------------------------

    @property
    def cookies(self) -> list[dict]:
        return list(self.storage_state.get("cookies", []))

    def cookies_for(self, url_or_host: str | None = None) -> list[dict]:
        """Cookies whose domain matches the given URL/host (suffix match, leading dot aware)."""
        if not url_or_host:
            return self.cookies
        host = _host(url_or_host) if "//" in url_or_host or "/" in url_or_host else url_or_host
        host = (host or "").lower()
        out = []
        for c in self.cookies:
            dom = str(c.get("domain", "")).lstrip(".").lower()
            if not dom or host == dom or host.endswith("." + dom) or dom.endswith(host):
                out.append(c)
        return out

    def cookie_header(self, url_or_host: str | None = None) -> str:
        pairs = [f"{c['name']}={c['value']}" for c in self.cookies_for(url_or_host) if c.get("name")]
        return "; ".join(pairs)

    def set_cookie(self, name: str, value: str, domain: str, path: str = "/") -> None:
        cookies = self.storage_state.setdefault("cookies", [])
        for c in cookies:
            if c.get("name") == name and str(c.get("domain", "")).lstrip(".") == domain.lstrip("."):
                c["value"] = value
                return
        cookies.append({"name": name, "value": value, "domain": domain, "path": path})

    # ----- persistence -------------------------------------------------------

    def session_storage_init_script(self) -> str | None:
        """A Playwright init-script that repopulates sessionStorage on every page load.
        storage_state can't carry sessionStorage, so token-in-sessionStorage SPAs (APP)
        need this to come back authenticated in a restored browser context."""
        if not self.session_storage:
            return None
        data = json.dumps(self.session_storage)
        return ("(() => { try { const d = " + data + "; "
                "for (const k in d) { window.sessionStorage.setItem(k, d[k]); } } catch (e) {} })();")

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "origin": self.origin,
            "storage_state": self.storage_state,
            "headers": self.headers,
            "session_storage": self.session_storage,
            "meta": self.meta,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Session:
        return cls(
            name=d.get("name", "session"),
            origin=d.get("origin", ""),
            storage_state=d.get("storage_state", {}),
            headers=d.get("headers", {}),
            session_storage=d.get("session_storage", {}),
            meta=d.get("meta", {}),
            captured_at=d.get("captured_at", ""),
        )

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def load(cls, path: str) -> Session:
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def summary(self) -> str:
        return (f"session {self.name!r} origin={self.origin} "
                f"cookies={len(self.cookies)} headers={len(self.headers)} "
                f"sessionStorage={len(self.session_storage)} "
                f"captured={self.captured_at} meta={self.meta}")
