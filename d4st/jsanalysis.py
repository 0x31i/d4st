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
    | [\w\-/]{1,}/[\w\-/]{1,}\.(?:aspx|asmx|ashx|php|jsp|json)  # path w/ ext (no do/action/api: FPs on minified JS division/props)
    | api/[\w\-/]{1,}                                            # api/... route
  )
  (?:"|'|`)
""", re.VERBOSE)

_API_HINT = re.compile(r"/api/|/rest/|/v\d+/|\.asmx|\.ashx", re.IGNORECASE)

# SPA API routes are built in template literals / concatenation, so the whole path is rarely a
# single quoted string — `${this.host}/rest/products/search?q=${e}` never sits between quotes.
# The quote-anchored _ENDPOINT_RE misses ALL of them (that's how Juice Shop's entire /rest +
# /api surface went undiscovered). This second pass finds API route segments anywhere in the
# JS regardless of delimiter, keyed on the distinctive /api|/rest|/graphql|/v<n> prefix.
_API_PATH_RE = re.compile(
    r"/(?:api|rest|graphql|internal|service|services|v\d+)"
    r"(?:/(?:\$\{[^}]{1,40}\}|[A-Za-z0-9_][\w.\-]*))+/?"
    r"(?:\?[\w\-.\[\]]+=(?:\$\{[^}]{1,40}\}|[\w%\-.]*))?",
    re.IGNORECASE,
)


def _norm_route(raw: str) -> str:
    """Turn a template-literal route into a concrete, testable path: replace ${...}
    interpolation with a placeholder value so path params resolve and query params survive
    (`/rest/products/search?q=${e}` -> `/rest/products/search?q=1`, so `q` gets fuzzed)."""
    return re.sub(r"\$\{[^}]*\}", "1", raw)


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
    # Compare hostname to hostname: `host` may carry a port (localhost:3000) while
    # urlsplit(...).hostname strips it, so a raw `hostname != host` check drops every same-host
    # endpoint on any non-443/80 target. Strip creds + port from both sides before comparing.
    want_host = (host or "").rsplit("@", 1)[-1].split(":")[0].lower()

    def _add(raw: str) -> None:
        raw = (raw or "").strip()
        if not raw or raw.startswith(("//cdn", "http://www.w3", "https://www.w3")):
            return
        url = urljoin(base_url, _norm_route(raw))
        h = (urlsplit(url).hostname or want_host).lower()
        if want_host and h != want_host:
            return
        # Drop minified-numeral junk: paths whose every segment is pure-numeric or a single
        # char (e.g. `/10`, `/2/5`) are array indices / loop counters lifted out of minified
        # code, never real routes. Keep `/rest/basket/1` (mixed) and `/2fa/enter` (alnum).
        segs = [s for s in urlsplit(url).path.split("/") if s]
        if segs and all(re.fullmatch(r"\d+|.", s) for s in segs):
            return
        if url in seen:
            return
        seen.add(url)
        out.append(url)

    for m in _ENDPOINT_RE.finditer(js_text or ""):
        _add(m.group(1))
    # Second pass: template-literal / concatenated API routes the quote-anchored regex can't see.
    for m in _API_PATH_RE.finditer(js_text or ""):
        _add(m.group(0))
    # API-looking endpoints first
    out.sort(key=lambda u: (not bool(_API_HINT.search(u)), u))
    return out


def detect_vuln_libs(js_text: str, url: str) -> list[VulnLib]:
    # Scan the WHOLE bundle, not just the first 4 KB: a webpack/Angular chunk inlines its vendored
    # libs anywhere in the body, so the version banner is rarely near the top (this is why Burp's
    # "Vulnerable JavaScript dependency" class was missed — we only sniffed the banner region).
    hay = f"{url}\n{js_text[:600000]}"
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


# ----- JS CONTENT disclosure scanning (Burp parity: connstrings, emails, hardcoded keys) --------
# These classes live in the SPA's chunk-*.js BODIES. The crawler reaches the chunks but nothing
# scanned their content (run_roster's gitleaks/trufflehog need a populated js_dir, which nothing
# filled). harvest_js_content() below downloads every in-scope chunk AND scans it for these.
_JS_SECRET_PATTERNS = [
    ("db-connection-string", "secret-disclosure", re.compile(
        r"(?i)(?:server|data\s*source)\s*=\s*[^;'\"<>\s]{2,60}\s*;\s*"
        r"(?:database|initial\s*catalog)\s*=\s*[^;'\"<>\s]{2,60}")),
    ("db-connection-string", "secret-disclosure", re.compile(
        r"(?i)(?:user\s*id|uid)\s*=\s*[^;'\"<>\s]{2,40}\s*;\s*(?:password|pwd)\s*=\s*[^;'\"<>\s]{2,40}")),
    ("google-api-key", "secret-disclosure", re.compile(r"AIza[0-9A-Za-z_\-]{20,}")),
    ("aws-access-key", "secret-disclosure", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private-key", "secret-disclosure", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\s]{80,}"
        r"-----END")),   # require real key BODY, not a bare format-marker string in a crypto lib
    ("azure-sas-endpoint", "info-disclosure", re.compile(
        r"(?i)getAccountSASToken|/api/SAS\b|[?&]sv=\d{4}-\d{2}-\d{2}&s[ir]=")),
    ("hardcoded-secret", "secret-disclosure", re.compile(
        r"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)"
        r"\"?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']")),
]
_JS_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_EMAIL_ASSET_SUFFIX = (".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".css", ".js", ".gif", ".ico")
_EMAIL_NOISE_PREFIX = ("example@", "test@", "user@", "email@", "name@", "your@", "you@",
                       "someone@", "sentry@", "john@", "jane@", "admin@example")
_EMAIL_NOISE_DOMAIN = ("example.com", "example.org", "example.net", "domain.com", "email.com",
                       "test.com", "sentry.io", "w3.org", "schema.org", "googleapis.com",
                       "localhost", "yourdomain.com", "company.com", "mysite.com")

# webpack/Angular lazily loads chunks — their filenames are string literals in the runtime/main
# bundle, so we can discover the FULL chunk set (not just the ones the crawler happened to trigger)
# by pulling every chunk-like .js reference out of each body and fetching it too.
_CHUNK_REF_RE = re.compile(
    r"(?:chunk|main|runtime|polyfills|vendor|scripts|common|styles)[.\-][A-Za-z0-9]{4,}\.js")


def scan_js_secrets(js_text: str, url: str) -> list[tuple[str, str, str]]:
    """Return [(label, category, evidence)] of secrets/PII disclosed in JS content — the Burp
    'Database connection string / Email addresses / hardcoded key' classes. Read-only; caller dedups."""
    text = js_text or ""
    out: list[tuple[str, str, str]] = []
    for label, cat, rx in _JS_SECRET_PATTERNS:
        for m in rx.finditer(text):
            out.append((label, cat, m.group(0)[:120]))
    for m in _JS_EMAIL_RE.finditer(text):
        e = m.group(0)
        low = e.lower()
        dom = low.rsplit("@", 1)[-1]
        if low.endswith(_EMAIL_ASSET_SUFFIX) or low.startswith(_EMAIL_NOISE_PREFIX):
            continue
        if dom in _EMAIL_NOISE_DOMAIN or "@2x" in low or "@3x" in low or low.count("@") != 1:
            continue
        out.append((e, "pii-disclosure", e))
    return out


def harvest_js_content(js_urls: list[str], cookie: str, host: str, out_dir: str,
                       extra_headers: dict | None = None, workers: int = 8,
                       max_files: int = 8000) -> tuple[int, list[dict], list[str], bool]:
    """DEEP JS pass: download EVERY in-scope JS bundle (no cap) + auto-expand to the full lazy-loaded
    chunk set discovered in the bundle bodies, saving each to out_dir (so run_roster's gitleaks/
    trufflehog scan real content) and scanning every body for secrets/PII/vuln-deps + API endpoints.
    Parallel fetch so 'scan everything' stays fast. Returns (n_saved, [finding], [endpoint], truncated).
    max_files is a runaway backstop only — if hit it is REPORTED (truncated=True), never silent."""
    import os
    from concurrent.futures import ThreadPoolExecutor
    from urllib.parse import urljoin, urlsplit

    import httpx
    os.makedirs(out_dir, exist_ok=True)
    hdr: dict = {}
    if cookie:
        hdr["Cookie"] = cookie
    if extra_headers:
        hdr.update({k: v for k, v in extra_headers.items() if k and v})
    origin = ""
    for u in js_urls:
        p = urlsplit(u)
        if p.scheme and p.netloc:
            origin = f"{p.scheme}://{p.netloc}"
            break

    findings: list[dict] = []
    endpoints: list[str] = []
    seen_find: set = set()
    seen_ep: set = set()
    seen_urls: set = set()
    queue: list[str] = list(dict.fromkeys(js_urls))
    saved = 0
    idx = 0
    truncated = False

    client = httpx.Client(verify=False, follow_redirects=True, timeout=15, headers=hdr)

    def _fetch(u: str):
        try:
            return u, client.get(u).text
        except Exception:  # noqa: BLE001, S112
            return u, None

    try:
        while queue:
            batch = [u for u in queue if u not in seen_urls]
            queue = []
            for u in batch:
                seen_urls.add(u)
            if not batch:
                break
            if saved >= max_files:
                truncated = True
                break
            batch = batch[:max_files - saved]
            for u, txt in ThreadPoolExecutor(max_workers=workers).map(_fetch, batch):
                if txt is None:
                    continue
                fn = os.path.join(out_dir, f"{idx:05d}_" + (u.rsplit("/", 1)[-1].split("?")[0] or "s"))
                idx += 1
                if not fn.endswith(".js"):
                    fn += ".js"
                try:
                    with open(fn, "w", encoding="utf-8") as fh:
                        fh.write(txt)
                    saved += 1
                except Exception:  # noqa: BLE001, S112
                    pass
                for vl in detect_vuln_libs(txt, u):
                    k = ("dep", vl.library, vl.version)
                    if k not in seen_find:
                        seen_find.add(k)
                        findings.append({"category": "vulnerable-js-dependency", "url": u,
                                         "param": vl.library,
                                         "detail": f"{vl.library} {vl.version}: {vl.detail}"})
                for label, cat, ev in scan_js_secrets(txt, u):
                    k = (cat, ev)
                    if k not in seen_find:
                        seen_find.add(k)
                        findings.append({"category": cat, "url": u, "param": label,
                                         "detail": f"{label} disclosed in JS: {ev}"})
                for ep in extract_endpoints(txt, u, host):
                    if ep not in seen_ep:
                        seen_ep.add(ep)
                        endpoints.append(ep)
                if origin:   # expand to lazy-loaded chunks referenced in this body
                    for m in _CHUNK_REF_RE.finditer(txt):
                        cu = urljoin(origin + "/", m.group(0))
                        if cu not in seen_urls:
                            queue.append(cu)
    finally:
        client.close()
    return saved, findings, endpoints, truncated


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


# ----- Semgrep static analysis over fetched JS (belt-and-suspenders for DOM flows) --------

def _semgrep_category(check_id: str, cwe) -> str:
    cid = (check_id or "").lower()
    text = f"{cid} {' '.join(cwe) if isinstance(cwe, list) else (cwe or '')}".lower()
    # specific subcategories first, then the broad xss catch-all
    if "redirect" in text or "cwe-601" in text:
        return "open-redirect"
    if "data-sink" in text or "data-manipulation" in text:
        return "dom-data-manipulation"
    if "secret" in text or "hardcoded" in text or "credential" in text or "cwe-798" in text:
        return "info-disclosure"
    if "prototype" in text or "cwe-1321" in text:
        return "prototype-pollution"
    if "xss" in text or "cwe-79" in text or "dom" in text or "eval" in text:
        return "xss"
    return "misconfiguration"


def parse_semgrep_json(text: str) -> list[dict]:
    import json
    text = (text or "").strip()
    if not text:
        return []
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for r in obj.get("results", []):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        out.append({
            "tool": "semgrep",
            "check": r.get("check_id"),
            "path": r.get("path"),
            "line": (r.get("start", {}) or {}).get("line"),
            "message": extra.get("message", ""),
            "category": _semgrep_category(r.get("check_id", ""), meta.get("cwe")),
        })
    return out


def run_semgrep_js(js_urls: list[str], cookie: str, semgrep_bin: str = "semgrep",
                   configs: list[str] | None = None, cap: int = 40) -> list[dict]:
    """Fetch the app's JS bundles and run Semgrep's JS/XSS rulesets over them — catches
    source->sink flows in code paths the runtime DOM pass never triggers. Runs Semgrep as a
    subprocess (it needs py3.10+), so it is decoupled from this 3.9-capable package.
    Returns [] if semgrep is absent (degrades gracefully)."""
    import os
    import shutil
    import subprocess
    import tempfile

    import httpx

    if not shutil.which(semgrep_bin) and not os.path.exists(semgrep_bin):
        return []
    import os as _os
    _local = _os.path.join(_os.path.dirname(__file__), "rules", "dom-xss.yaml")
    configs = configs or ["p/javascript", "p/secrets", _local]
    headers = {"Cookie": cookie} if cookie else {}
    workdir = tempfile.mkdtemp(prefix="semgrep_js_")
    n = 0
    for i, u in enumerate(js_urls[:cap]):
        try:
            r = httpx.get(u, headers=headers, follow_redirects=True, timeout=12)
        except Exception:  # noqa: BLE001, S112
            continue
        fn = os.path.join(workdir, f"{i:03d}_" + (u.split("/")[-1].split("?")[0] or "script") )
        if not fn.endswith(".js"):
            fn += ".js"
        try:
            with open(fn, "w", encoding="utf-8") as fh:
                fh.write(r.text)
            n += 1
        except Exception:  # noqa: BLE001, S112
            continue
    if not n:
        return []
    args = [semgrep_bin, "--json", "--quiet", "--timeout", "30", "--metrics", "off"]
    for c in configs:
        args += ["--config", c]
    args.append(workdir)
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=600, check=False)
    except Exception:  # noqa: BLE001
        return []
    return parse_semgrep_json(proc.stdout)
