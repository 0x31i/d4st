"""Headless DOM analysis — the client-side gap our HTTP probes cannot see.

Hardened apps (like the FHC EHR) surface DOM-based findings: DOM XSS, DOM-based open
redirection, DOM data manipulation. These execute in client-side JS from sources like
location.hash / location.search, so a plain HTTP replay never triggers them. This drives a
real headless browser (Playwright): it injects a marker payload into DOM sources and confirms
whether it reaches a sink (script execution) or drives a navigation to an attacker URL.

Playwright imported lazily; if browsers are absent it degrades to "not run".
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

_XSS_MARK = "__dom_xss_hit__"
_EVIL = "https://evil.example/x"


@dataclass
class DomFinding:
    category: str          # xss | open-redirect
    url: str
    source: str            # hash | param:<name>
    evidence: str


def _cookies_for(cookie: str, host: str) -> list[dict]:
    out = []
    for kv in (cookie or "").split(";"):
        kv = kv.strip()
        if "=" in kv:
            n, v = kv.split("=", 1)
            out.append({"name": n.strip(), "value": v.strip(), "domain": host, "path": "/"})
    return out


def dom_probe(url: str, cookie: str = "", params: list[str] | None = None,
              timeout_ms: int = 8000) -> list[DomFinding]:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001
        return []

    host = urlsplit(url).hostname or ""
    params = params or []
    base = url.split("#")[0].split("?")[0]
    xss_payload = f"<img src=x onerror=window.{_XSS_MARK}=1>"
    findings: list[DomFinding] = []

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)
        except Exception:  # noqa: BLE001 - browsers not installed
            return []
        ctx = browser.new_context()
        if cookie:
            try:
                ctx.add_cookies(_cookies_for(cookie, host))
            except Exception:  # noqa: BLE001
                pass
        page = ctx.new_page()
        page.add_init_script(f"window.{_XSS_MARK}=0;")

        state = {"evil": False}
        # Record ONLY a real top-level navigation toward the attacker origin (not the injected
        # hash sitting in the current URL, and not subresource requests) -> true DOM redirect.
        def _route(route):
            req = route.request
            try:
                is_nav_doc = req.resource_type == "document" and req.is_navigation_request()
            except Exception:  # noqa: BLE001
                is_nav_doc = False
            if "evil.example" in req.url and is_nav_doc:
                state["evil"] = True
                try:
                    route.abort()
                    return
                except Exception:  # noqa: BLE001
                    pass
            try:
                route.continue_()
            except Exception:  # noqa: BLE001
                pass
        page.route("**/*", _route)

        def _load(u):
            try:
                page.goto(u, wait_until="load", timeout=timeout_ms)
                page.wait_for_timeout(500)
                return True
            except Exception:  # noqa: BLE001
                return False

        # --- DOM XSS: hash source + each query param. add_init_script re-zeroes the marker on
        # every navigation, so a post-load read of 1 means the payload executed. ---
        sources = [("hash", f"{base}#{xss_payload}")]
        for pn in params:
            sources.append((f"param:{pn}", f"{base}?{pn}={xss_payload}"))
        for src, u in sources:
            if not _load(u):
                continue
            try:
                if page.evaluate(f"window.{_XSS_MARK}") == 1:
                    findings.append(DomFinding("xss", u, src, "payload reached a DOM sink (executed)"))
            except Exception:  # noqa: BLE001, S112
                continue

        # --- DOM open redirect: hash + redirect-ish params drive navigation to evil. Confirm
        # via an intercepted top-level navigation OR the document actually landing on evil. ---
        redir_sources = [("hash", f"{base}#{_EVIL}")]
        for pn in params:
            if pn.lower() in {"redirect", "url", "next", "return", "dest", "go", "target",
                              "returnurl", "redir", "continue", "forward"}:
                redir_sources.append((f"param:{pn}", f"{base}?{pn}={_EVIL}"))
        for src, u in redir_sources:
            state["evil"] = False
            _load(u)
            landed = (urlsplit(page.url or "").hostname == "evil.example")
            if state["evil"] or landed:
                findings.append(DomFinding("open-redirect", u, src,
                                           "DOM navigation to attacker-controlled URL"))

        browser.close()
    # dedup by (category, source)
    seen, uniq = set(), []
    for f in findings:
        k = (f.category, f.source)
        if k not in seen:
            seen.add(k); uniq.append(f)
    return uniq
