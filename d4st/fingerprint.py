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

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .scope import in_scope as _scope_in_scope, scope_hosts

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


@dataclass
class AttackProfile:
    """Fingerprint -> PROBE strategy. Derived from an AppProfile, consumed by the engagement to
    ADD app-appropriate deep techniques on top of the full baseline roster (never to remove
    coverage — thoroughness only goes up). This is the object that lets the scanner 'detect the
    type of web app and adjust how it probes'.

    - is_php/java/aspnet/node: stack-specific payload emphasis (php:// wrappers, EL/OGNL, web.config).
    - dom_xss: run the DOM source->sink check (cheap + high-value; on for every app).
    - api_mode: emphasise the API/GraphQL/JWT tools (schemathesis/jwt_tool/graphw00f) that are
      pointless on a form app but essential on a JSON/OpenAPI backend.
    """
    app_type: str = 'unknown'
    tech: list[str] = field(default_factory=list)
    is_php: bool = False
    is_java: bool = False
    is_aspnet: bool = False
    is_node: bool = False
    dom_xss: bool = True
    api_mode: bool = False

    def summary(self) -> str:
        stacks = [n for n, on in (('php', self.is_php), ('java', self.is_java),
                                  ('aspnet', self.is_aspnet), ('node', self.is_node)) if on]
        extras = [n for n, on in (('dom-xss', self.dom_xss), ('api-tools', self.api_mode)) if on]
        return (f"attack-profile: stack={'/'.join(stacks) or 'generic'} "
                f"emphasis={'+'.join(extras) or 'baseline'}")


def build_attack_profile(appprof: 'AppProfile | None') -> AttackProfile:
    """Map a crawl-time AppProfile into a probe-time AttackProfile. Fail-safe: a missing profile
    yields a generic profile that still runs the full baseline (DOM-XSS on, no API emphasis)."""
    if appprof is None:
        return AttackProfile()
    tech = ' '.join(appprof.tech).lower()
    return AttackProfile(
        app_type=appprof.app_type,
        tech=list(appprof.tech),
        is_php='php' in tech or 'laravel' in tech or 'codeigniter' in tech,
        is_java='java' in tech or 'jsp' in tech or 'servlet' in tech,
        is_aspnet='asp' in tech or 'iis' in tech,
        is_node='node' in tech or 'express' in tech,
        dom_xss=True,   # the DOM source->sink check is cheap and catches what nothing else does
        api_mode=(appprof.app_type == 'api'),
    )


def _get(url: str, cookie: str, timeout: int = 12):
    if requests is None:
        return None
    from .safety import browser_headers
    headers = browser_headers({'Cookie': cookie} if cookie else None)
    try:
        return requests.get(url, headers=headers, timeout=timeout,
                            allow_redirects=True, verify=False)
    except Exception:
        return None


# Common second-level public-suffix labels (the `co` in example.CO.UK). Keeps the
# registrable-domain guess from collapsing a ccTLD site down to a bare ccTLD.
_MULTI_SLD = frozenset({'co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'gob', 'or', 'ne'})


def _registrable_domain(host: str) -> str:
    """Best-effort registrable domain (eTLD+1) without a public-suffix list.

    'www.bristolglobal.com' -> 'bristolglobal.com'; 'app.example.co.uk' ->
    'example.co.uk'. Fail-safe by design: a host we cannot reduce is returned
    unchanged, and the ccTLD guard errs toward KEEPING more labels (a narrower
    scope), so a bad guess never widens scope past the host itself.
    """
    h = (host or '').lower().strip('.')
    labels = [p for p in h.split('.') if p]
    if len(labels) < 3:
        return h  # 'example.com' or a bare/host-less value — already minimal
    # ccTLD + known second level (example.co.uk) keeps three labels.
    if len(labels[-1]) == 2 and labels[-2] in _MULTI_SLD:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def _in_scope(url: str, hosts) -> bool:
    """In-scope iff the URL's host matches an engagement scope host or is a
    subdomain of one — the SAME subdomain-aware test the live crawl applies
    (scope.in_scope). Using it here keeps the fingerprint from under-counting a
    surface the crawl itself would accept (e.g. a cross-subdomain redirect).
    Relative / host-less URLs resolve against the target and stay in-scope."""
    return _scope_in_scope(url, hosts)


def _count_anchors(body: str, base: str, hosts) -> tuple[int, list[str]]:
    """Count in-scope, in-page navigation links (ignoring fragments/mailto/js).

    `base` is the FINAL (post-redirect) landing URL so relative anchors resolve
    against where we actually landed, and `hosts` is the subdomain-aware scope
    list, so anchors on a sibling/parent/child subdomain of the landing host
    are counted rather than silently dropped by an exact-host test."""
    links = []
    for href in _ANCHOR.findall(body or ''):
        href = href.strip()
        if not href or href.startswith(('#', 'mailto:', 'javascript:', 'tel:')):
            continue
        absu = urljoin(base, href)
        if urlsplit(absu).scheme in ('http', 'https') and _in_scope(absu, hosts):
            links.append(absu.split('#')[0])
    return len(set(links)), sorted(set(links))


def _discover_entry_seeds(base: str, body: str, cookie: str, hosts,
                          signals: list[str]) -> list[str]:
    """When the landing page is link-poor, find real entry points from robots.txt,
    sitemap.xml, in-page text path hints, and conventional index files. Only keep a
    candidate if it returns 200 AND exposes MORE in-scope links than the seed did.

    `base` is the FINAL landing URL (post-redirect), so robots/sitemap and the
    conventional index files are discovered relative to where we actually landed
    (e.g. the www host after an apex->www redirect), and `hosts` is the
    subdomain-aware scope list used to keep candidates in-scope."""
    root = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}/"
    base_path = base.rsplit('/', 1)[0] + '/'
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
        if c in seen or not _in_scope(c, hosts):
            continue
        seen.add(c)
        if len(seen) > 40:  # hard probe budget — never hammer a real target
            break
        rr = _get(c, cookie, timeout=8)
        if rr is None or rr.status_code != 200:
            continue
        n, _ = _count_anchors(rr.text, c, hosts)
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

    # The fetch follows redirects (allow_redirects=True), so `body` is the REAL
    # landing page. Anchor counting + seed discovery must therefore use the FINAL
    # landing URL as their base, and a subdomain-aware scope derived from where we
    # landed — otherwise a cross-subdomain redirect (apex 301=>www) leaves base/
    # want_host on the original host, every landing-page anchor fails an exact-host
    # test, and a site with a full surface reads as "link-poor" (links=1).
    try:
        landing = str(r.url) or target
    except Exception:  # noqa: BLE001
        landing = target
    base = landing
    landing_host = (urlsplit(landing).hostname or want_host or '').lower()

    # Scope for anchor counting + seed discovery:
    #   * explicit engagement scope (D4ST_SCOPE_HOSTS) is honored EXACTLY and
    #     never widened — same list scope.scope_hosts() hands the live crawl;
    #   * otherwise derive a subdomain-aware scope from the registrable domain of
    #     BOTH the requested host and the landing host, so a cross-subdomain
    #     redirect and sibling/parent/child subdomains are in-scope, matching
    #     scope.in_scope instead of the old exact-host match.
    if os.environ.get('D4ST_SCOPE_HOSTS', '').strip():
        scope = scope_hosts(target)
    else:
        scope = []
        for _h in (want_host, landing_host):
            _reg = _registrable_domain(_h)
            if _reg and _reg not in scope:
                scope.append(_reg)

    # tech from headers
    for h, fn in _HEADER_TECH.items():
        if h in {k.lower() for k in r.headers}:
            val = next(v for k, v in r.headers.items() if k.lower() == h)
            if val:
                prof.tech.append(fn(val))
    # tech from cookies — response Set-Cookie AND the session cookie WE ALREADY HOLD. An
    # authenticated scan does not get a fresh Set-Cookie (the session already exists), so keying
    # only off the response misses the stack; the cookie we send (PHPSESSID/JSESSIONID/...) names
    # it just as reliably.
    for ck, label in _COOKIE_TECH.items():
        if (ck in r.cookies or re.search(rf'\b{re.escape(ck)}\b', r.headers.get('set-cookie', ''))
                or re.search(rf'\b{re.escape(ck)}\b', cookie or '')):
            prof.tech.append(label)
    # tech from server-rendered link extensions (.php/.jsp/.aspx in the body) — the stack a page
    # tree advertises even when headers/cookies are stripped.
    _ext_tech = {'php': 'PHP', 'jsp': 'Java/JSP (servlet container)', 'jspx': 'Java/JSP',
                 'aspx': 'ASP.NET', 'asp': 'Classic ASP', 'cfm': 'ColdFusion',
                 'do': 'Java (Struts)', 'action': 'Java (Struts)'}
    for _m in re.findall(r'\.(php|jsp|jspx|aspx?|cfm|do|action)\b', body, re.I):
        prof.tech.append(_ext_tech.get(_m.lower(), _m))

    n_links, _ = _count_anchors(body, base, scope)
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
        prof.entry_seeds = _discover_entry_seeds(base, body, cookie, scope, prof.signals)
        # Reclassify spa=>mpa ONLY when the discovered pages are themselves server-rendered
        # (.jsp/.php/.aspx) AND there is no framework-root marker. A true SPA has a link-less
        # shell BY DESIGN, so finding a stray richer page must never downgrade a page whose
        # raw HTML carries an <app-root>/<div id=root>/ng-version marker (that stays headless).
        server_seeds = [s for s in prof.entry_seeds if _SERVER_EXT.search(s)]
        if prof.app_type == 'spa' and server_seeds and not spa_body:
            prof.app_type = 'mpa'
            prof.headless = False
            prof.signals.append('reclassified spa=>mpa: server-rendered page tree, no framework root')

    # Capture the redirect LANDING url as a crawl seed whenever the fetch landed
    # somewhere other than the requested target. Two cases, both otherwise lost:
    #   * a cross-subdomain redirect (apex 301=>www) — the landing host carries
    #     the real surface and must seed the crawl even without a query string;
    #   * a login/return flow (OWA 302s to logon.aspx?url=...&reason=0) whose
    #     reflected return-URL param is a real injection point.
    # Scope is the subdomain-aware engagement scope, so an off-scope redirect
    # (e.g. to an IdP) is still correctly refused.
    try:
        seed = (landing or '').split('#')[0]
        if (seed and seed != target
                and _in_scope(seed, scope)
                and seed not in prof.entry_seeds):
            prof.entry_seeds.append(seed)
            _q = urlsplit(seed).query
            prof.signals.append(
                'redirect landing captured as seed '
                f'({urlsplit(seed).path}{"?" + _q if _q else ""})')
    except Exception:  # noqa: BLE001
        pass

    # de-dup tech, keep order
    prof.tech = list(dict.fromkeys(prof.tech))
    return prof
