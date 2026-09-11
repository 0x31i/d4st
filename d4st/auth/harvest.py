"""Authenticated API-surface harvest for token SPAs.

katana's headless crawl can't carry sessionStorage, so a JWT-in-sessionStorage SPA (EHRM) bounces
it to /login and the blind crawl finds nothing behind auth. This drives Playwright with the RESTORED
session (cookies + localStorage + sessionStorage + bearer header), navigates the app's routes, and
captures every same-origin XHR/fetch the SPA makes at runtime — the real API surface the scanners
should hit. It also follows same-origin in-app anchors to reach more routes.

Returns {api_calls, frontier, routes_visited}: api_calls carry method + url + post body so the
engagement can seed authenticated injection targets (not just GET URLs)."""

from __future__ import annotations

from urllib.parse import urlsplit

from .session import Session


def harvest(session: Session, base: str, routes: list[str] | None = None, *,
            max_routes: int = 25, per_route_ms: int = 3500, timeout_ms: int = 45000) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001
        return {"api_calls": [], "frontier": [], "routes_visited": [], "error": f"playwright: {exc}"}

    origin = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"
    seen: dict[str, dict] = {}
    visited: set[str] = set()
    init = session.session_storage_init_script()
    to_visit = list(dict.fromkeys((routes or []) + ["/", "/provider/new"]))

    def _record(r) -> None:
        if r.resource_type in ("xhr", "fetch") and r.url.startswith(origin):
            key = f"{r.method} {r.url}"
            if key not in seen:
                try:
                    body = r.post_data
                except Exception:
                    body = None
                seen[key] = {"method": r.method, "url": r.url, "body": body}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(storage_state=session.storage_state or None, ignore_https_errors=True)
        if init:
            ctx.add_init_script(init)
        if session.headers:
            try:
                ctx.set_extra_http_headers(session.headers)
            except Exception:
                pass
        page = ctx.new_page()
        page.on("request", _record)
        try:
            page.goto(origin, wait_until="networkidle", timeout=timeout_ms)  # bootstrap the SPA
        except Exception:
            pass

        # Angular route table lives in the JS bundle — harvest non-parameterized route paths so we
        # visit the whole app, not just what's linked. (Parameterized routes like patient/:id need
        # an id, skipped here; the API calls off the pages we DO reach still expose those params.)
        import re as _re
        route_re = _re.compile(r"""path\s*:\s*['"]([A-Za-z0-9][A-Za-z0-9_\-/]*)['"]""")
        try:
            scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)") or []
        except Exception:
            scripts = []
        for src in scripts:
            if origin in src and src.endswith(".js"):
                try:
                    txt = page.evaluate("async (u) => { const r = await fetch(u); return await r.text(); }", src)
                except Exception:
                    txt = ""
                for m in set(route_re.findall(txt or "")):
                    if ":" in m or m in ("", "**"):
                        continue
                    r2 = "/" + m.strip("/")
                    if r2 and r2 not in visited and r2 not in to_visit:
                        to_visit.append(r2)

        i = 0
        while to_visit and i < max_routes:
            route = to_visit.pop(0)
            if route in visited:
                continue
            visited.add(route)
            i += 1
            try:
                page.goto(origin + route, wait_until="networkidle", timeout=timeout_ms)
                page.wait_for_timeout(per_route_ms)
            except Exception:
                continue
            # discover more in-app routes: <a href> AND Angular [routerLink] (SPAs nav via the latter)
            hrefs = []
            for sel, attr in (("a[href]", "href"), ("[routerLink]", "routerLink")):
                try:
                    hrefs += page.eval_on_selector_all(sel, f"els => els.map(e => e.getAttribute('{attr}'))") or []
                except Exception:
                    pass
            for h in hrefs:
                if not h or not isinstance(h, str):
                    continue
                if h.startswith(origin):
                    h = h[len(origin):]
                if h.startswith("/") and " " not in h and ":" not in h and h not in visited and h not in to_visit:
                    to_visit.append(h)
        browser.close()

    return {
        "api_calls": list(seen.values()),
        "frontier": sorted({v["url"] for v in seen.values()}),
        "routes_visited": sorted(visited),
    }
