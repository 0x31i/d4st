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
_TAINT = "tnt9x7k2z0"      # marker injected into a DOM source; watched at sinks

# Client-side taint harness (DOM-Invader-lite): hooks common DOM sinks and records when a
# value containing the taint marker reaches them. Catches "DOM data manipulation" — tainted
# source data flowing into a non-executing sink (cookie, storage, attribute, field value,
# innerHTML) — the class our HTTP probes and even the XSS check don't cover.
_TAINT_HARNESS = r"""
(function(){
  var M = "%MARK%";
  window.__domtaint = [];
  function rec(sink){ try { if (window.__domtaint.indexOf(sink)===-1) window.__domtaint.push(sink); } catch(e){} }
  function tainted(v){ try { return typeof v==='string' && v.indexOf(M)!==-1; } catch(e){ return false; } }
  function hookProp(obj, prop, label){
    try {
      var d = Object.getOwnPropertyDescriptor(obj, prop);
      if (d && d.set){
        Object.defineProperty(obj, prop, {
          configurable:true, get:d.get,
          set:function(v){ if(tainted(v)) rec(label); return d.set.call(this, v); }
        });
      }
    } catch(e){}
  }
  // sinks: cookie, storage, setAttribute, innerHTML/outerHTML, input/anchor value+href
  try{ var cd = Object.getOwnPropertyDescriptor(Document.prototype,'cookie'); if(cd&&cd.set){
    Object.defineProperty(document,'cookie',{configurable:true,get:cd.get,
      set:function(v){ if(tainted(v)) rec('document.cookie'); return cd.set.call(document,v); }}); } }catch(e){}
  try{ var si=Storage.prototype.setItem; Storage.prototype.setItem=function(k,v){ if(tainted(v)) rec('storage.setItem'); return si.apply(this,arguments); }; }catch(e){}
  try{ var sa=Element.prototype.setAttribute; Element.prototype.setAttribute=function(n,v){ if(tainted(v)) rec('setAttribute('+n+')'); return sa.apply(this,arguments); }; }catch(e){}
  hookProp(Element.prototype,'innerHTML','innerHTML');
  hookProp(Element.prototype,'outerHTML','outerHTML');
  try{ hookProp(HTMLInputElement.prototype,'value','input.value'); }catch(e){}
  try{ hookProp(HTMLAnchorElement.prototype,'href','anchor.href'); }catch(e){}
})();
""".replace("%MARK%", _TAINT)


@dataclass
class DomFinding:
    category: str          # xss | open-redirect | dom-data-manipulation
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
        page.add_init_script(_TAINT_HARNESS)

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

        # --- DOM data manipulation: inject a taint marker into a source, see which sinks
        # receive it (cookie/storage/attribute/value/innerHTML). Non-executing flows Burp
        # reports as "DOM data manipulation". ---
        taint_sources = [("hash", f"{base}#{_TAINT}")]
        for pn in params:
            taint_sources.append((f"param:{pn}", f"{base}?{pn}={_TAINT}"))
        for src, u in taint_sources:
            if not _load(u):
                continue
            try:
                sinks = page.evaluate("window.__domtaint || []")
            except Exception:  # noqa: BLE001, S112
                continue
            for sink in sinks or []:
                findings.append(DomFinding("dom-data-manipulation", u, src,
                                           f"tainted {src} reaches DOM sink: {sink}"))

        browser.close()
    # dedup by (category, source)
    seen, uniq = set(), []
    for f in findings:
        k = (f.category, f.source)
        if k not in seen:
            seen.add(k); uniq.append(f)
    return uniq
