"""JavaScript analysis: API/endpoint discovery + vulnerable-dependency detection.

Hardened apps (like the FHC EHR) expose their real surface through JS-driven API calls, not
HTML links, and their notable finding is often a vulnerable JS library. This module:
- extract_endpoints(): pull URLs/paths/API routes out of JS (LinkFinder-style), so /api/...
  routes get discovered and tested even when nothing links to them.
- detect_vuln_libs(): identify library + version and flag known-vulnerable versions
  (retire.js-lite). Covers the "Vulnerable JavaScript dependency" class.

Pure stdlib + a small curated vuln table; unit-testable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

# LinkFinder-style endpoint regex (simplified, robust).
_ENDPOINT_RE = re.compile(r"""
  (?:"|'|`)
  (
    (?:[a-zA-Z]{1,10}://|//)[^"'`/]{1,}\.[a-zA-Z]{2,}[^"'`]{0,}   # absolute URL
    | (?:/|\.\./|\./)[\w\-/]{1,}[^"'`><,; )(]{0,}                 # rooted / relative path
    | [\w\-/]{1,}/[\w\-/]{1,}\.(?:aspx|asmx|ashx|php|jsp|json|action|do|api)  # path w/ ext
    | api/[\w\-/]{1,}                                            # api/... route
  )
  (?:"|'|`)
""", re.VERBOSE)

_API_HINT = re.compile(r"/api/|/rest/|/v\d+/|\.asmx|\.ashx|GetInfo|GetInfo", re.IGNORECASE)


@dataclass
class VulnLib:
    library: str
    version: str
    url: str
    detail: str


# retire.js-lite: library -> (detect regex on url/content, "vulnerable if < this version").
# Small but real: the common libs with well-known client-side CVEs.
_LIB_SIGNATURES = [
    ("jquery", re.compile(r"jquery[.-]?v?(\d+\.\d+\.\d+)", re.IGNORECASE), "3.5.0",
     "jQuery < 3.5.0: XSS via htmlPrefilter / DOMPurify bypass (CVE-2020-11022/23)"),
    ("jquery", re.compile(r"/\*!\s*jQuery v(\d+\.\d+\.\d+)", re.IGNORECASE), "3.5.0",
     "jQuery < 3.5.0: XSS (CVE-2020-11022/11023)"),
    ("bootstrap", re.compile(r"bootstrap[.-]?v?(\d+\.\d+\.\d+)", re.IGNORECASE), "3.4.1",
     "Bootstrap < 3.4.1: XSS in data-target / tooltip (CVE-2019-8331 etc.)"),
    ("angular", re.compile(r"angular[.-]?v?(\d+\.\d+\.\d+)", re.IGNORECASE), "1.8.0",
     "AngularJS < 1.8.0: multiple XSS/sandbox-escape issues"),
    ("lodash", re.compile(r"lodash[.-]?v?(\d+\.\d+\.\d+)", re.IGNORECASE), "4.17.21",
     "lodash < 4.17.21: prototype pollution (CVE-2019-10744 etc.)"),
    ("moment", re.compile(r"moment[.-]?v?(\d+\.\d+\.\d+)", re.IGNORECASE), "2.29.4",
     "moment < 2.29.4: ReDoS / path traversal (CVE-2022-31129)"),
    ("kendo", re.compile(r"kendo[.\w]*?(\d{4}\.\d+\.\d+)", re.IGNORECASE), "2020.1.114",
     "Kendo UI older build: known XSS in widgets; verify against vendor advisories"),
]


def _ver_tuple(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v))


def extract_endpoints(js_text: str, base_url: str, host: str) -> list[str]:
    """Return same-host absolute URLs referenced in JS (API routes prioritized)."""
    out: list[str] = []
    seen: set = set()
    for m in _ENDPOINT_RE.finditer(js_text or ""):
        raw = m.group(1).strip()
        if not raw or raw.startswith(("//cdn", "http://www.w3", "https://www.w3")):
            continue
        url = urljoin(base_url, raw)
        if (urlsplit(url).hostname or host) != host:
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append(url)
    # API-looking endpoints first
    out.sort(key=lambda u: (not bool(_API_HINT.search(u)), u))
    return out


def detect_vuln_libs(js_text: str, url: str) -> list[VulnLib]:
    hay = f"{url}\n{js_text[:4000]}"  # filename + banner region
    found: list[VulnLib] = []
    seen: set = set()
    for lib, rx, floor, detail in _LIB_SIGNATURES:
        m = rx.search(hay)
        if not m:
            continue
        ver = m.group(1)
        if lib in seen:
            continue
        try:
            if _ver_tuple(ver) < _ver_tuple(floor):
                seen.add(lib)
                found.append(VulnLib(library=lib, version=ver, url=url, detail=detail))
        except Exception:  # noqa: BLE001, S112
            continue
    return found


def analyze_js(js_urls: list[str], cookie: str, host: str,
               cap: int = 30) -> tuple[list[str], list[VulnLib]]:
    """Fetch JS files, return (discovered_endpoints, vulnerable_libs)."""
    import httpx
    headers = {"Cookie": cookie} if cookie else {}
    endpoints: list[str] = []
    vulns: list[VulnLib] = []
    seen_ep: set = set()
    for u in js_urls[:cap]:
        try:
            r = httpx.get(u, headers=headers, follow_redirects=True, timeout=12)
        except Exception:  # noqa: BLE001, S112
            continue
        for ep in extract_endpoints(r.text, str(r.url), host):
            if ep not in seen_ep:
                seen_ep.add(ep)
                endpoints.append(ep)
        vulns += detect_vuln_libs(r.text, str(r.url))
    return endpoints, vulns
