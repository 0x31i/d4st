"""Pre-flight target fingerprinting + adaptive crawl-strategy selection.

The scanner must decide, WITHOUT a human watching, two things the crawl gets
wrong on its own:

  1. Headless or plain?  Headless (a real browser) is how you reach an SPA's
     runtime /api + /rest surface, but it is slow and pointless on a
     server-rendered app (JSP/PHP/ASP) whose links are already in the raw HTML.
     Running headless on a server-rendered app wastes time; running plain on an
     SPA misses everything behind the router.

  2. Where do I actually start?  Some landing pages have few or no links (a
     framework shell that builds the DOM client-side, or a deliberately
     link-less index like WAVSEP's). Seeding the crawl there yields ~one URL.
     The real entry points have to be discovered from robots.txt, sitemap.xml,
     in-page text hints, and a short list of conventional index files.

`fingerprint_target()` fetches a handful of read-only GETs, classifies the app,
and returns an AppProfile the engagement uses to configure the crawl. Everything
here is fail-safe: any error yields a conservative default (plain crawl, seed as
the only entry point) rather than sinking the scan.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

try:
    import requests
except Exception:  # pragma: no cover - requests is a hard dep in practice
    requests = None


# ---- signal tables -----------------------------------------------------------

# SPA framework markers in the raw HTML body (client-rendered => needs headless).
_SPA_BODY = (
    re.compile(r'<div[^>]+id=["\'](?:root|app|__next|__nuxt|q-app)["\']', re.I),
    re.compile(r'<app-root[\s>]', re.I),
    re.compile(r'\bng-version=', re.I),
    re.compile(r'\bdata-reactroot\b', re.I),
    re.compile(r'\b__NEXT_DATA__\b'),
    re.compile(r'window\.__NUXT__'),
    re.compile(r'window\.__INITIAL_STATE__'),
)
# Bundled-JS markers: a hashed main/runtime/chunk bundle is an SPA build artifact.
_SPA_BUNDLE = re.compile(
    r'<script[^>]+src=["\'][^"\']*'
    r'(?:runtime|main|polyfills|vendor|chunk|bundle)[.\-][^"\']*\.js', re.I)

# Server-rendered extensions in links => the raw HTML already carries navigation.
_SERVER_EXT = re.compile(r'\.(?:jsp|php|aspx?|do|action|cfm|jspx)\b', re.I)
_ANCHOR = re.compile(r'<a\s[^>]*href=["\']([^"\']+)["\']', re.I)
_FORM = re.compile(r'<form\b', re.I)

# Tech fingerprints from response headers + cookies.
_HEADER_TECH = {
    'x-powered-by': lambda v: v,
    'server': lambda v: v,
    'x-aspnet-version': lambda v: f'ASP.NET {v}',
    'x-generator': lambda v: v,
    'x-drupal-cache': lambda v: 'Drupal',
}
_COOKIE_TECH = {
    'JSESSIONID': 'Java/JSP (servlet container)',
    'PHPSESSID': 'PHP',
    'ASP.NET_SessionId': 'ASP.NET',
    'ASPSESSIONID': 'Classic ASP',
    'laravel_session': 'Laravel/PHP',
    'ci_session': 'CodeIgniter/PHP',
    'connect.sid': 'Node/Express',
}

# In-page text path hints: a deliberately link-less index (WAVSEP) still NAMES its
# entry pages as plain text ("active/index-sql.jsp"). Harvest those as seeds too.
_TEXT_PATH = re.compile(r'\b((?:[\w\-]+/){0,6}[\w\-]+\.(?:jsp|php|aspx?|html?|do|action))\b', re.I)

# Conventional entry files to probe when the landing page is link-poor.
_CONVENTIONAL = (
    'index.jsp', 'index-active.jsp', 'active/index-main.jsp',
    'index.php', 'index.html', 'home', 'main', 'app', 'dashboard',
    'api', 'api/', 'swagger.json', 'openapi.json', 'sitemap.xml',
)

# A landing page with this few in-scope anchors is "link-poor" => discover seeds.
_LINK_POOR = 3


@dataclass
class AppProfile:
    target: str
    app_type: str = 'unknown'          # 'spa' | 'mpa' | 'api' | 'unknown'
    tech: list[str] = field(default_factory=list)
    headless: bool = False             # recommended crawl mode
    entry_seeds: list[str] = field(default_factory=list)  # extra crawl roots
    seed_link_count: int = 0
    signals: list[str] = field(default_factory=list)      # human-readable "why"

    def summary(self) -> str:
        seeds = f", +{len(self.entry_seeds)} discovered entry seed(s)" if self.entry_seeds else ""
        tech = f" [{', '.join(self.tech)}]" if self.tech else ""
        return (f"app={self.app_type} crawl={'headless' if self.headless else 'plain'}"
                f"{tech} links={self.seed_link_count}{seeds}")


def _get(url: str, cookie: str, timeout: int = 12):
    if requests is None:
        return None
    headers = {'User-Agent': 'dastng-fingerprint/1.0'}
    if cookie:
        headers['Cookie'] = cookie
    try:
        return requests.get(url, headers=headers, timeout=timeout,
                            allow_redirects=True, verify=False)
    except Exception:
        return None


def _in_scope(url: str, want_host: str) -> bool:
    h = (urlsplit(url).hostname or '').lower()
    return h == want_host or not h  # relative URLs resolve in-scope


def _count_anchors(body: str, base: str, want_host: str) -> tuple[int, list[str]]:
    """Count in-scope, in-page navigation links (ignoring fragments/mailto/js)."""
    links = []
    for href in _ANCHOR.findall(body or ''):
        href = href.strip()
        if not href or href.startswith(('#', 'mailto:', 'javascript:', 'tel:')):
            continue
        absu = urljoin(base, href)
        if urlsplit(absu).scheme in ('http', 'https') and _in_scope(absu, want_host):
            links.append(absu.split('#')[0])
    return len(set(links)), sorted(set(links))


def _discover_entry_seeds(target: str, body: str, cookie: str, want_host: str,
                          signals: list[str]) -> list[str]:
    """When the landing page is link-poor, find real entry points from robots.txt,
    sitemap.xml, in-page text path hints, and conventional index files. Only keep a
    candidate if it returns 200 AND exposes MORE in-scope links than the seed did."""
    root = f"{urlsplit(target).scheme}://{urlsplit(target).netloc}/"
    base_path = target.rsplit('/', 1)[0] + '/'
    candidates: list[str] = []

    # (a) robots.txt Disallow/Allow paths + Sitemap directives.
    r = _get(urljoin(root, 'robots.txt'), cookie, timeout=8)
    if r is not None and r.status_code == 200 and 'text' in r.headers.get('content-type', ''):
        for m in re.finditer(r'(?im)^\s*(?:dis)?allow\s*:\s*(\S+)', r.text):
            candidates.append(urljoin(root, m.group(1)))
        for m in re.finditer(r'(?im)^\s*sitemap\s*:\s*(\S+)', r.text):
            candidates.append(m.group(1).strip())

    # (b) sitemap.xml <loc> entries.
    sm = _get(urljoin(root, 'sitemap.xml'), cookie, timeout=8)
    if sm is not None and sm.status_code == 200:
        try:
            for el in ET.fromstring(sm.text).iter():
                if el.tag.endswith('loc') and el.text:
                    candidates.append(el.text.strip())
        except Exception:
            pass

    # (c) in-page TEXT path hints (link-less index that names its pages as text).
    for m in _TEXT_PATH.findall(body or ''):
        candidates.append(urljoin(base_path, m))

    # (d) conventional index files, relative to both site root and the seed dir.
    for name in _CONVENTIONAL:
        candidates.append(urljoin(base_path, name))
        candidates.append(urljoin(root, name))

    # Validate: keep in-scope 200s that are richer than the seed. Cap the probe budget.
    seen, kept = set(), []
    for c in candidates:
        c = c.split('#')[0]
        if c in seen or not _in_scope(c, want_host):
            continue
        seen.add(c)
        if len(seen) > 40:  # hard probe budget — never hammer a real target
            break
        rr = _get(c, cookie, timeout=8)
        if rr is None or rr.status_code != 200:
            continue
        n, _ = _count_anchors(rr.text, c, want_host)
        if n > _LINK_POOR:
            kept.append(c)
    if kept:
        signals.append(f"link-poor landing => discovered {len(kept)} richer entry seed(s)")
    return kept[:8]  # a handful of strong roots is enough; the crawl expands from there


def fingerprint_target(target: str, host: str, cookie: str = '') -> AppProfile:
    """Fetch a few read-only GETs, classify the app, and recommend a crawl strategy.
    Fail-safe: on any error returns a conservative plain-crawl profile."""
    want_host = (host or urlsplit(target).netloc or '').rsplit('@', 1)[-1].split(':')[0].lower()
    prof = AppProfile(target=target)

    r = _get(target, cookie)
    if r is None:
        prof.signals.append('seed fetch failed => conservative plain crawl')
        return prof

    body = r.text or ''
    ctype = r.headers.get('content-type', '').lower()

    # tech from headers
    for h, fn in _HEADER_TECH.items():
        if h in {k.lower() for k in r.headers}:
            val = next(v for k, v in r.headers.items() if k.lower() == h)
            if val:
                prof.tech.append(fn(val))
    # tech from cookies
    for ck, label in _COOKIE_TECH.items():
        if ck in r.cookies or re.search(rf'\b{re.escape(ck)}\b', r.headers.get('set-cookie', '')):
            prof.tech.append(label)

    n_links, _ = _count_anchors(body, target, want_host)
    prof.seed_link_count = n_links
    spa_body = any(rx.search(body) for rx in _SPA_BODY)
    spa_bundle = bool(_SPA_BUNDLE.search(body))
    server_ext = bool(_SERVER_EXT.search(body)) or any(
        'PHP' in t or 'JSP' in t or 'ASP' in t or 'Java' in t for t in prof.tech)

    # ---- classify -----------------------------------------------------------
    if 'json' in ctype or urlsplit(target).path.rstrip('/').endswith(('/api', 'openapi.json', 'swagger.json')):
        prof.app_type = 'api'
        prof.headless = False
        prof.signals.append(f'JSON/OpenAPI content-type ({ctype})')
    elif (spa_body or spa_bundle) and n_links <= _LINK_POOR and not server_ext:
        prof.app_type = 'spa'
        prof.headless = True
        prof.signals.append(
            'SPA markers (' + ', '.join(
                s for s, ok in (('framework-root', spa_body), ('js-bundle', spa_bundle)) if ok)
            + f') + link-poor raw DOM ({n_links})')
    elif server_ext or n_links > _LINK_POOR:
        prof.app_type = 'mpa'
        prof.headless = False
        prof.signals.append(
            f'server-rendered (links={n_links}, ext={"yes" if server_ext else "no"})')
    else:
        # ambiguous: few links, no clear framework, no server ext. Default plain but
        # flag for entry-seed discovery below.
        prof.app_type = 'unknown'
        prof.headless = False
        prof.signals.append(f'ambiguous (links={n_links}); default plain crawl')

    # ---- entry-seed discovery for link-poor landings ------------------------
    if n_links <= _LINK_POOR and prof.app_type != 'api':
        prof.entry_seeds = _discover_entry_seeds(target, body, cookie, want_host, prof.signals)
        # Reclassify spa=>mpa ONLY when the discovered pages are themselves server-rendered
        # (.jsp/.php/.aspx) AND there is no framework-root marker. A true SPA has a link-less
        # shell BY DESIGN, so finding a stray richer page must never downgrade a page whose
        # raw HTML carries an <app-root>/<div id=root>/ng-version marker (that stays headless).
        server_seeds = [s for s in prof.entry_seeds if _SERVER_EXT.search(s)]
        if prof.app_type == 'spa' and server_seeds and not spa_body:
            prof.app_type = 'mpa'
            prof.headless = False
            prof.signals.append('reclassified spa=>mpa: server-rendered page tree, no framework root')

    # de-dup tech, keep order
    prof.tech = list(dict.fromkeys(prof.tech))
    return prof
