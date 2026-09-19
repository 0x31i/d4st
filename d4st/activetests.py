"""Active depth tests that share one httpx client + the shared evidence shape:

  - run_cors_checks()   : turn "CORS present" noise into a VERIFIED exploitable/benign verdict —
                          does the server reflect an arbitrary Origin AND allow credentials?
  - run_verb_tampering(): method/verb-based access-control gaps (BFLA). SAFE by default — only
                          read-ish methods (OPTIONS/HEAD + method/case variants on ALREADY-protected
                          endpoints to catch verb-tampering auth bypass). Write-method probing
                          (POST/PUT/DELETE) is OPT-IN via D4ST_METHOD_TAMPER_WRITES=1 (never mutates
                          client data by default).
  - assess_secrets()    : elevate a disclosed key from "found" to scoped impact. Static classification
                          by default; a live restriction check runs only under D4ST_SECRET_VALIDATE=1.

All read-only unless explicitly opted in; throttled; every finding carries full evidence + repro.
"""

from __future__ import annotations

import os
import re
import time
from urllib.parse import urlsplit

from .evidence import curl, exchange, synthetic_exchange

_EVIL_ORIGIN = "https://d4st-cors-probe.example.org"


def _auth_header_name(session) -> str:
    for k in getattr(session, "headers", {}) or {}:
        if k.lower() == "authorization":
            return k
    return "Authorization"


def _authed_headers(session, base: str) -> dict:
    h = dict(getattr(session, "headers", {}) or {})
    try:
        ck = session.cookie_header(base)
        if ck:
            h["Cookie"] = ck
    except Exception:  # noqa: BLE001
        pass
    return h


# ---------------------------------------------------------------- CORS ----
def run_cors_checks(session, base: str, urls: list[str], *,
                    delay: float = 0.15, timeout: float = 12.0, max_urls: int = 25,
                    throttle=None) -> list[dict]:
    """Send a cross-origin request with an attacker Origin and judge the CORS response. Reflecting
    an arbitrary Origin WITH Access-Control-Allow-Credentials:true is exploitable (any site can read
    the victim's authenticated responses). ACAO:* is weaker (no creds). One consolidated finding."""
    import httpx

    from .safety import pace

    origin = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"
    cand = [u for u in urls if u.startswith(origin) and "/api/" in u.lower()] or \
           [u for u in urls if u.startswith(origin)]
    cand = cand[:max_urls]
    if not cand:
        return []

    authed = _authed_headers(session, base)
    findings: list[dict] = []
    reflected: list[tuple[str, object]] = []
    null_ok: list[tuple[str, object]] = []
    wildcard_creds: list[tuple[str, object]] = []

    with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as c:
        for u in cand:
            for test_origin in (_EVIL_ORIGIN, "null"):
                try:
                    r = c.get(u, headers={**authed, "Origin": test_origin})
                    pace(throttle, delay, r.status_code)
                except Exception:  # noqa: BLE001
                    continue
                acao = r.headers.get("access-control-allow-origin", "")
                acac = (r.headers.get("access-control-allow-credentials", "") or "").lower() == "true"
                if acao == test_origin and test_origin == _EVIL_ORIGIN:
                    reflected.append((u, r))
                    if acac:
                        wildcard_creds.append((u, r))
                elif acao == "null" and test_origin == "null":
                    null_ok.append((u, r))
                elif acao == "*" and acac:
                    wildcard_creds.append((u, r))
            if reflected and wildcard_creds:
                break  # enough proof

    def _mk(kind, sev, sample, detail):
        u, r = sample
        return {
            "type": kind, "name": kind, "severity": sev, "url": u, "method": "GET",
            "category": "cors-misconfiguration", "verified": True,
            "detail": detail,
            "evidence_log": [exchange("Cross-origin request with attacker Origin — server response "
                                      "reflects it", r)],
            "repro": curl(r),
        }

    if wildcard_creds:
        u, r = wildcard_creds[0]
        findings.append(_mk(
            "cors-credentialed-reflection", "high", (u, r),
            f"the server reflects an arbitrary Origin ('{_EVIL_ORIGIN}' or '*') AND returns "
            f"Access-Control-Allow-Credentials: true on {len(wildcard_creds)} endpoint(s). Any "
            f"attacker-controlled website can issue authenticated cross-origin requests and READ the "
            f"victim's responses — a genuine exploitable CORS misconfiguration (not the benign "
            f"'header present' that a naive scan reports)."))
    elif reflected:
        u, r = reflected[0]
        findings.append(_mk(
            "cors-origin-reflection", "medium", (u, r),
            f"the server reflects an arbitrary request Origin in Access-Control-Allow-Origin on "
            f"{len(reflected)} endpoint(s) WITHOUT allow-credentials. Lower impact (no cookie/cred "
            f"read) but still allows cross-origin reads of any non-credentialed response."))
    elif null_ok:
        u, r = null_ok[0]
        findings.append(_mk(
            "cors-null-origin", "medium", (u, r),
            "the server allows the 'null' Origin (sandboxed iframes / redirects / local files). "
            "A page in a null-origin context can make cross-origin reads. Review."))
    return findings


# --------------------------------------------------- verb / method tampering ----
_SAFE_METHODS = ["OPTIONS", "HEAD"]
_CASE_VARIANTS = ["Get", "GET ", "get"]   # verb-tampering auth-bypass (filter often matches exact "GET")
_WRITE_METHODS = ["POST", "PUT", "PATCH", "DELETE"]


def run_verb_tampering(session, base: str, urls: list[str], *,
                       delay: float = 0.2, timeout: float = 12.0, max_endpoints: int = 120,
                       throttle=None) -> list[dict]:
    """Detect method/verb-based broken access control (BFLA). SAFE default: for endpoints that are
    protected (401/403 unauth), retry unauthenticated with HEAD and method-case variants — if any
    returns data, the auth filter is method-specific (classic verb-tampering bypass). Also enumerate
    server-advertised methods via OPTIONS. Write-method probing only under D4ST_METHOD_TAMPER_WRITES=1."""
    import httpx

    from .safety import pace

    origin = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"
    api = [u for u in urls if u.startswith(origin) and "/api/" in u.lower()][:max_endpoints]
    if not api:
        return []
    authed = _authed_headers(session, base)
    noauth = {k: v for k, v in authed.items() if k.lower() not in ("authorization", "cookie")}
    do_writes = os.environ.get("D4ST_METHOD_TAMPER_WRITES") == "1"
    findings: list[dict] = []
    seen: set[str] = set()

    with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as c:
        for u in api:
            if u in seen:
                continue
            seen.add(u)
            # baseline: authed GET (oracle) + unauth GET (is it protected?)
            try:
                a = c.get(u, headers=authed); pace(throttle, delay, a.status_code)
                n = c.request("GET", u, headers=noauth); pace(throttle, delay, n.status_code)
            except Exception:  # noqa: BLE001
                continue
            if a.status_code >= 400:
                continue
            protected = n.status_code in (401, 403)

            # 1) verb-tampering auth bypass (SAFE — HEAD + GET-case only, unauthenticated)
            if protected:
                for meth in _SAFE_METHODS + _CASE_VARIANTS:
                    try:
                        rr = c.request(meth.strip() or "GET", u, headers=noauth)
                        pace(throttle, delay, rr.status_code)
                    except Exception:  # noqa: BLE001
                        continue
                    # a protected GET (401/403) that answers <400 to a different method/case = bypass
                    if rr.status_code < 400 and rr.status_code != n.status_code:
                        findings.append({
                            "type": "verb-tampering-auth-bypass", "name": "verb-tampering-auth-bypass",
                            "severity": "high", "url": u, "method": meth.strip() or "GET",
                            "category": "broken-access-control", "verified": True,
                            "detail": f"endpoint returns {n.status_code} to an unauthenticated GET but "
                                      f"{rr.status_code} to an unauthenticated '{meth.strip() or 'GET'}' "
                                      f"request — the authorization filter is method-specific and can be "
                                      f"bypassed by altering the HTTP method/case.",
                            "evidence_log": [
                                exchange("Unauthenticated GET (correctly rejected)", n),
                                exchange(f"Unauthenticated '{meth.strip() or 'GET'}' (BYPASS — accepted)", rr)],
                            "repro": curl(rr),
                        })
                        break

            # 2) advertised-method enumeration (informational, safe)
            try:
                opt = c.request("OPTIONS", u, headers=authed); pace(throttle, delay, opt.status_code)
                allow = opt.headers.get("allow") or opt.headers.get("access-control-allow-methods") or ""
            except Exception:  # noqa: BLE001
                allow = ""
            if allow and any(m in allow.upper() for m in _WRITE_METHODS):
                findings.append({
                    "type": "http-methods-advertised", "name": "http-methods-advertised",
                    "severity": "info", "url": u, "method": "OPTIONS",
                    "category": "misconfiguration", "verified": True,
                    "detail": f"OPTIONS advertises state-changing methods on this data endpoint: "
                              f"Allow/ACAM = '{allow}'. Confirm each is authorization-gated.",
                    "evidence_log": [exchange("OPTIONS — advertised methods", opt)],
                    "repro": curl(opt),
                })

            # 3) OPT-IN write-method BFLA (never mutates unless the operator explicitly enables it)
            if do_writes:
                for meth in _WRITE_METHODS:
                    try:
                        wr = c.request(meth, u, headers=authed); pace(throttle, delay, wr.status_code)
                    except Exception:  # noqa: BLE001
                        continue
                    if wr.status_code < 400:
                        findings.append({
                            "type": "bfla-write-method", "name": "bfla-write-method",
                            "severity": "high", "url": u, "method": meth,
                            "category": "broken-access-control", "verified": True,
                            "detail": f"{meth} on a read endpoint returned {wr.status_code} (not "
                                      f"405/403) — the function-level access control may permit "
                                      f"state-changing operations. (D4ST_METHOD_TAMPER_WRITES=1)",
                            "evidence_log": [exchange(f"{meth} request (authed)", wr)],
                            "repro": curl(wr),
                        })
                        break
    return findings


# ---------------------------------------------------- host-header injection ----
_HHI_HOST = "d4st-hhi-probe.example.org"


def run_host_header_injection(session, base: str, urls: list[str], *,
                              delay: float = 0.2, timeout: float = 12.0, max_urls: int = 25,
                              throttle=None) -> list[dict]:
    """Send requests with a poisoned Host / X-Forwarded-Host and see if the attacker value comes
    back in a redirect Location, an absolute URL in the body, or a Set-Cookie domain. Reflection
    means host-header injection — the root of password-reset poisoning, web-cache poisoning, and
    routing-based SSRF. READ-ONLY GET; throttled."""
    import httpx
    from urllib.parse import urlsplit as _us

    from .safety import pace
    origin = f"{_us(base).scheme}://{_us(base).netloc}"
    cand = [u for u in urls if u.startswith(origin)][:max_urls]
    if not cand:
        return []
    authed = _authed_headers(session, base)
    findings: list[dict] = []
    with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as c:
        for u in cand:
            for hdr in ("Host", "X-Forwarded-Host"):
                try:
                    r = c.get(u, headers={**authed, hdr: _HHI_HOST})
                    pace(throttle, delay, r.status_code)
                except Exception:  # noqa: BLE001
                    continue
                loc = r.headers.get("location", "")
                setck = " ".join(r.headers.get_list("set-cookie")) if hasattr(r.headers, "get_list") else ""
                where = ("redirect Location" if _HHI_HOST in loc else
                         "Set-Cookie domain" if _HHI_HOST in setck else
                         "response body" if _HHI_HOST in (r.text or "") else "")
                if where:
                    findings.append({
                        "type": "host-header-injection", "name": "host-header-injection",
                        "severity": "medium", "url": u, "method": "GET",
                        "category": "host-header-injection", "verified": True,
                        "detail": f"a poisoned '{hdr}: {_HHI_HOST}' request header is reflected back in "
                                  f"the {where} — host-header injection. Enables password-reset-link "
                                  f"poisoning, web-cache poisoning, and routing-based SSRF depending on "
                                  f"how the app uses the host value.",
                        "evidence_log": [exchange(f"PROOF — poisoned {hdr} reflected in {where}", r)],
                        "repro": curl(r),
                    })
                    return findings  # one solid proof is enough; avoid flooding
    return findings


_CSPP_MARK = "d4stZ9"


def run_cspp_checks(session, base: str, urls: list[str], *,
                    delay: float = 0.2, timeout: float = 12.0, max_urls: int = 25,
                    throttle=None) -> list[dict]:
    """Client-side HTTP parameter pollution (CSPP). For each in-scope URL that carries query
    parameters, inject a canary value that DECODES to '<mark>&cspp=1' into one parameter and see
    whether the app reflects it into a link/form URL WITHOUT re-encoding — i.e. an extra '&cspp=1'
    parameter appears inside an href/src/action query string in the page. If it does, an attacker
    can add or override parameters on the URLs a victim clicks. Canary-verified (near-zero FP):
    we only report when our injected parameter actually materialises in a page URL. READ-ONLY GET."""
    import httpx
    from urllib.parse import parse_qsl, quote
    from urllib.parse import urlsplit as _us
    from urllib.parse import urlunsplit

    from .safety import pace
    origin = f"{_us(base).scheme}://{_us(base).netloc}"
    cand: list = []
    for u in urls:
        if not u.startswith(origin):
            continue
        sp = _us(u)
        if sp.query:
            cand.append(sp)
        if len(cand) >= max_urls:
            break
    if not cand:
        return []
    authed = _authed_headers(session, base)
    inj = f"{_CSPP_MARK}%26cspp%3d1"   # sent as-is in the query; server decodes to <mark>&cspp=1
    # a page URL where our injected param landed inside a query string
    hit_re = re.compile(r'(?:href|src|action)\s*=\s*["\'][^"\']*[?&]cspp=1\b', re.IGNORECASE)
    findings: list[dict] = []
    with httpx.Client(verify=False, follow_redirects=True, timeout=timeout) as c:
        for sp in cand:
            params = parse_qsl(sp.query, keep_blank_values=True)
            for i, (pn, _pv) in enumerate(params):
                qparts = [f"{k}={inj}" if j == i else f"{k}={quote(vv, safe='')}"
                          for j, (k, vv) in enumerate(params)]
                test_url = urlunsplit((sp.scheme, sp.netloc, sp.path, "&".join(qparts), ""))
                try:
                    r = c.get(test_url, headers=authed)
                    pace(throttle, delay, r.status_code)
                except Exception:  # noqa: BLE001
                    continue
                body = r.text or ""
                if _CSPP_MARK in body and hit_re.search(body):
                    findings.append({
                        "type": "client-side-param-pollution",
                        "name": "client-side-param-pollution",
                        "severity": "medium", "url": test_url, "method": "GET",
                        "category": "client-side-param-pollution", "verified": True,
                        "detail": f"parameter '{pn}' is reflected into a page link's query string "
                                  f"without encoding — our injected '&cspp=1' appears as a distinct "
                                  f"parameter on a URL in the response (client-side HTTP parameter "
                                  f"pollution). An attacker can add or override query parameters on "
                                  f"links/forms the victim interacts with.",
                        "evidence_log": [exchange(
                            f"PROOF — injected '&cspp=1' via '{pn}' reflected into a page URL", r)],
                        "repro": curl(r),
                    })
                    return findings   # one canary-verified proof is enough
    return findings


_BACKUP_SUFFIXES = (".bak", ".old", ".orig", ".save", ".copy", ".tmp", ".1",
                    ".zip", ".gz", ".tar.gz", ".rar", ".7z")


def _looks_like_file(path: str) -> bool:
    seg = path.rsplit("/", 1)[-1]
    return "." in seg and not path.endswith("/")


def _body_sig(r) -> tuple:
    """Coarse content signature to compare a hit against the catch-all baseline."""
    body = r.text or ""
    return (r.status_code, len(body) // 64, hash(body[:256]))


def _backup_variants(url: str) -> list[str]:
    from urllib.parse import urlsplit as _us
    from urllib.parse import urlunsplit
    sp = _us(url)
    p = sp.path
    seg = p.rsplit("/", 1)[-1]
    base_dir = p[: len(p) - len(seg)]
    paths = [base_dir + seg + suf for suf in _BACKUP_SUFFIXES]
    paths.append(base_dir + seg + "~")            # editor backup
    paths.append(base_dir + "." + seg + ".swp")   # vim swap file
    if "." in seg:
        stem = seg.rsplit(".", 1)[0]
        paths.append(base_dir + stem + ".bak")
        paths.append(base_dir + stem + ".zip")
    seen: set = set()
    out: list[str] = []
    for pp in paths:
        if pp in seen:
            continue
        seen.add(pp)
        out.append(urlunsplit((sp.scheme, sp.netloc, pp, "", "")))
    return out


def run_backup_scan(session, base: str, urls: list[str], *,
                    delay: float = 0.2, timeout: float = 12.0, max_files: int = 30,
                    max_hits: int = 12, throttle=None) -> list[dict]:
    """Probe backup/temp permutations of discovered files (name.ext.bak/.old/~/.swp/.zip/...).
    Guards against the OWA-style catch-all responder that makes commercial scanners report dozens
    of phantom 'backup file' hits: first establish whether the server returns 200 for random
    non-existent *.bak paths, and if so only report a variant whose body DIFFERS from that
    catch-all baseline. READ-ONLY GET; throttled; capped."""
    import secrets

    import httpx
    from urllib.parse import urlsplit as _us

    from .safety import pace
    origin = f"{_us(base).scheme}://{_us(base).netloc}"
    files: list[str] = []
    seen_files: set = set()
    for u in urls:
        if not u.startswith(origin):
            continue
        sp = _us(u)
        key = sp.path
        if _looks_like_file(sp.path) and key not in seen_files:
            seen_files.add(key)
            files.append(f"{sp.scheme}://{sp.netloc}{sp.path}")
        if len(files) >= max_files:
            break
    if not files:
        return []
    authed = _authed_headers(session, base)
    findings: list[dict] = []
    with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as c:
        # Catch-all / soft-404 baseline: do random non-existent *.bak paths return 200?
        catchall_sigs: list = []
        catchall = False
        for _ in range(2):
            probe = f"{origin}/d4st_{secrets.token_hex(8)}.bak"
            try:
                rp = c.get(probe, headers=authed)
            except Exception:  # noqa: BLE001
                rp = None
            if rp is not None and rp.status_code == 200:
                catchall = True
                catchall_sigs.append(_body_sig(rp))
        for f in files:
            for variant in _backup_variants(f):
                try:
                    r = c.get(variant, headers=authed)
                    pace(throttle, delay, r.status_code)
                except Exception:  # noqa: BLE001
                    continue
                if r.status_code != 200 or not (r.text or "").strip():
                    continue
                # FP guard: on a catch-all server, a real backup must differ from the baseline body
                if catchall and _body_sig(r) in catchall_sigs:
                    continue
                findings.append({
                    "type": "backup-file-exposure", "name": "backup-file-exposure",
                    "severity": "medium", "url": variant, "method": "GET",
                    "category": "info-disclosure", "verified": True,
                    "detail": f"a backup/temporary copy is directly accessible ({variant}) — returns "
                              f"HTTP 200 with content"
                              + (" that differs from the server's catch-all response" if catchall else "")
                              + ". Backup/temp files frequently expose source code, credentials, or "
                              "configuration.",
                    "evidence_log": [exchange("PROOF — backup/temp file accessible over HTTP", r)],
                    "repro": curl(r),
                })
                if len(findings) >= max_hits:
                    return findings
                break  # one backup variant per file is enough proof
    return findings


_XFORM_MARK = "d4stX9"
_XF_A, _XF_B = 419, 823          # distinctive operands; product 344837 is unlikely to occur naturally


def run_transformation_checks(session, base: str, urls: list[str], *,
                              delay: float = 0.2, timeout: float = 12.0, max_urls: int = 25,
                              max_params: int = 4, max_hits: int = 10, throttle=None) -> list[dict]:
    """Suspicious input transformation (Burp's check). For each in-scope URL with query parameters,
    inject marker-anchored probes and detect when the app TRANSFORMS the input in a security-relevant
    way:
      * expression/template evaluation — '<mark>{{419*823}}' (and ${..}/#{..}/<%=..%> variants) comes
        back as '<mark>344837' => the app evaluated our expression (server-side template injection).
      * string-escape transformation — '<mark>'' comes back backslash-escaped ('<mark>\\'') or a
        backslash is doubled => our input lands in a string-parsing context (SQL/JS injection tell).
    Marker-anchored => near-zero FP (HTML output-encoding produces &#39;/&quot;, not these). READ-ONLY
    GET; throttled; capped."""
    import httpx
    from urllib.parse import parse_qsl, quote
    from urllib.parse import urlsplit as _us
    from urllib.parse import urlunsplit

    from .safety import pace
    origin = f"{_us(base).scheme}://{_us(base).netloc}"
    cand: list = []
    for u in urls:
        if u.startswith(origin):
            sp = _us(u)
            if sp.query:
                cand.append(sp)
        if len(cand) >= max_urls:
            break
    if not cand:
        return []
    authed = _authed_headers(session, base)
    product = str(_XF_A * _XF_B)
    ssti_payloads = [
        f"{_XFORM_MARK}{{{{{_XF_A}*{_XF_B}}}}}",   # {{419*823}}
        f"{_XFORM_MARK}${{{_XF_A}*{_XF_B}}}",       # ${419*823}
        f"{_XFORM_MARK}#{{{_XF_A}*{_XF_B}}}",       # #{419*823}
        f"{_XFORM_MARK}<%={_XF_A}*{_XF_B}%>",       # <%=419*823%>
        f"{_XFORM_MARK}{{{_XF_A}*{_XF_B}}}",        # {419*823}
    ]

    def build(sp, idx, val, params):
        qparts = [f"{k}={quote(val, safe='')}" if j == idx else f"{k}={quote(vv, safe='')}"
                  for j, (k, vv) in enumerate(params)]
        return urlunsplit((sp.scheme, sp.netloc, sp.path, "&".join(qparts), ""))

    findings: list[dict] = []
    with httpx.Client(verify=False, follow_redirects=True, timeout=timeout) as c:
        for sp in cand:
            params = parse_qsl(sp.query, keep_blank_values=True)
            done = False
            for i, (pn, _pv) in enumerate(params[:max_params]):
                # (1) expression/template evaluation — strongest signal, report as SSTI
                for pay in ssti_payloads:
                    try:
                        r = c.get(build(sp, i, pay, params), headers=authed)
                        pace(throttle, delay, r.status_code)
                    except Exception:  # noqa: BLE001
                        continue
                    if (_XFORM_MARK + product) in (r.text or ""):
                        findings.append({
                            "type": "server-side-template-injection",
                            "name": "suspicious-input-transformation (expression evaluated)",
                            "severity": "high", "url": build(sp, i, pay, params), "method": "GET",
                            "category": "server-side-template-injection", "verified": True,
                            "detail": f"parameter '{pn}' is evaluated server-side: our injected "
                                      f"expression '{pay[len(_XFORM_MARK):]}' returned as "
                                      f"'{_XFORM_MARK}{product}' ({_XF_A}*{_XF_B}={product}). The "
                                      "application evaluates input as a template/expression — "
                                      "server-side template injection, frequently escalating to RCE.",
                            "evidence_log": [exchange(
                                f"PROOF — '{pn}' expression evaluated to {product}", r)],
                            "repro": curl(r),
                        })
                        done = True
                        break
                if done:
                    break
                # (2) string-escape transformation — quote/backslash escaping (SQL/JS string context)
                for probe, escaped, kind in (
                        (_XFORM_MARK + "'", _XFORM_MARK + "\\'", "single-quote backslash-escaped"),
                        (_XFORM_MARK + "\\", _XFORM_MARK + "\\\\", "backslash doubled")):
                    try:
                        r = c.get(build(sp, i, probe, params), headers=authed)
                        pace(throttle, delay, r.status_code)
                    except Exception:  # noqa: BLE001
                        continue
                    if escaped in (r.text or ""):
                        findings.append({
                            "type": "suspicious-input-transformation",
                            "name": "suspicious-input-transformation (string escaping)",
                            "severity": "medium", "url": build(sp, i, probe, params), "method": "GET",
                            "category": "suspicious-input-transformation", "verified": True,
                            "detail": f"parameter '{pn}' is transformed in a string-parsing context "
                                      f"({kind}): our input came back escaped rather than "
                                      "output-encoded. Input reaching a SQL/JS string context this "
                                      "way is a classic injection precursor — probe for SQLi/JS "
                                      "injection on this parameter.",
                            "evidence_log": [exchange(
                                f"PROOF — '{pn}' {kind}", r)],
                            "repro": curl(r),
                        })
                        done = True
                        break
                if done:
                    break
            if len(findings) >= max_hits:
                break
    return findings


_REFL_MARK = "d4stR3f"


def _reflect_context(body: str, token: str) -> str:
    idx = body.find(token)
    if idx < 0:
        return "html"
    pre = body[max(0, idx - 400):idx].lower()
    if pre.rfind("<script") > pre.rfind("</script"):
        return "javascript"
    if re.search(r'=\s*["\'][^"\'<>]*$', body[max(0, idx - 60):idx]):
        return "attribute"
    return "html"


def run_reflection_checks(session, base: str, urls: list[str], *,
                          delay: float = 0.2, timeout: float = 12.0, max_urls: int = 30,
                          max_hits: int = 15, throttle=None) -> list[dict]:
    """Reflected-input surface map (Burp's 'Input returned in response'). For each in-scope URL with
    query parameters, inject a unique canary and report where it is reflected verbatim, classifying
    the context (JavaScript / HTML attribute / HTML body) — the context determines XSS potential.
    Canary-verified (near-zero FP): reported only when our exact token appears in the response.
    READ-ONLY GET; throttled; capped. This maps the injection surface; active XSS confirmation is
    left to the roster (dalfox/nuclei)."""
    import secrets

    import httpx
    from urllib.parse import parse_qsl, quote
    from urllib.parse import urlsplit as _us
    from urllib.parse import urlunsplit

    from .safety import pace
    origin = f"{_us(base).scheme}://{_us(base).netloc}"
    cand: list = []
    for u in urls:
        if u.startswith(origin):
            sp = _us(u)
            if sp.query:
                cand.append(sp)
        if len(cand) >= max_urls:
            break
    if not cand:
        return []
    authed = _authed_headers(session, base)
    sev_by_ctx = {"javascript": "medium", "attribute": "low", "html": "low"}
    findings: list[dict] = []
    with httpx.Client(verify=False, follow_redirects=True, timeout=timeout) as c:
        for sp in cand:
            params = parse_qsl(sp.query, keep_blank_values=True)
            for i, (pn, _pv) in enumerate(params):
                token = _REFL_MARK + secrets.token_hex(4)
                qparts = [f"{k}={token}" if j == i else f"{k}={quote(vv, safe='')}"
                          for j, (k, vv) in enumerate(params)]
                test_url = urlunsplit((sp.scheme, sp.netloc, sp.path, "&".join(qparts), ""))
                try:
                    r = c.get(test_url, headers=authed)
                    pace(throttle, delay, r.status_code)
                except Exception:  # noqa: BLE001
                    continue
                body = r.text or ""
                if token not in body:
                    continue
                ctx = _reflect_context(body, token)
                findings.append({
                    "type": "reflected-input", "name": "reflected-input",
                    "severity": sev_by_ctx[ctx], "url": test_url, "method": "GET",
                    "category": "reflected-input", "verified": True,
                    "detail": f"parameter '{pn}' is reflected verbatim into the response in a "
                              f"{ctx} context. Reflected input is the precursor to cross-site "
                              f"scripting" + (" — a JavaScript context is directly XSS-relevant"
                                              if ctx == "javascript" else "") + "; confirm with "
                              "context-appropriate payloads.",
                    "evidence_log": [exchange(
                        f"PROOF — canary '{token}' reflected via '{pn}' ({ctx} context)", r)],
                    "repro": curl(r),
                })
                if len(findings) >= max_hits:
                    return findings
                break   # one reflection point per URL is enough for the surface map
    return findings


# ---------------------------------------------------- secret live-validation ----
_KEY_KINDS = [
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{20,}")),
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("stripe-key", re.compile(r"sk_(live|test)_[0-9A-Za-z]{16,}")),
    ("slack-token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
]


def assess_secrets(findings: list, *, delay: float = 0.3, timeout: float = 10.0) -> list[dict]:
    """For disclosed keys already found (JS/secret findings), add a scoped IMPACT assessment. Static
    by default; D4ST_SECRET_VALIDATE=1 does a live restriction check (calls the vendor API with the
    client's OWN key — off by default because it egresses to a third party)."""
    live = os.environ.get("D4ST_SECRET_VALIDATE") == "1"
    out: list[dict] = []
    seen: set[str] = set()
    for f in findings or []:
        blob = " ".join(str(getattr(f, x, "") or "") for x in ("evidence", "payload", "raw_output")) \
            if not isinstance(f, dict) else " ".join(str(f.get(x, "") or "") for x in ("detail", "evidence", "payload"))
        for kind, rx in _KEY_KINDS:
            m = rx.search(blob)
            if not m:
                continue
            key = m.group(0)
            if key in seen:
                continue
            seen.add(key)
            url = getattr(f, "url", "") if not isinstance(f, dict) else f.get("url", "")
            if kind == "google-api-key":
                out.append(_assess_google(key, url, live, delay, timeout))
            else:
                out.append({
                    "type": "secret-impact", "name": "secret-impact", "severity": "high",
                    "url": url, "method": "GET", "category": "secret-disclosure", "verified": False,
                    "detail": f"disclosed {kind} '{key[:6]}…{key[-4:]}'. Assess scope/permissions and "
                              f"rotate. (Automated live validation supported for google-api-key; "
                              f"others flagged for manual scope review.)",
                    "evidence_log": [synthetic_exchange(f"disclosed {kind}", method="GET", url=url,
                                                         resp_body=f"{kind}: {key[:6]}…{key[-4:]}")],
                    "repro": "# rotate this credential; verify least-privilege scoping",
                })
    return out


def _assess_google(key: str, url: str, live: bool, delay: float, timeout: float) -> dict:
    masked = f"{key[:8]}…{key[-4:]}"
    if not live:
        return {
            "type": "secret-impact", "name": "secret-impact", "severity": "medium",
            "url": url, "method": "GET", "category": "secret-disclosure", "verified": False,
            "detail": f"disclosed Google API key {masked}. Impact depends on API + HTTP-referrer/IP "
                      f"restrictions: an UNrestricted Maps/Geocoding key allows billable API abuse "
                      f"against the client's account. Set D4ST_SECRET_VALIDATE=1 to live-check "
                      f"restrictions, or verify in the Google Cloud console that the key is referrer/"
                      f"API-restricted. Rotate regardless (it is public in the JS bundle).",
            "evidence_log": [synthetic_exchange("disclosed Google API key (static assessment)",
                                                method="GET", url=url, resp_body=f"key: {masked}")],
            "repro": "# GCP console → APIs & Services → Credentials → restrict + rotate the key",
        }
    import httpx
    probe = ("https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre&key=" + key)
    try:
        with httpx.Client(verify=False, timeout=timeout) as c:
            r = c.get(probe); time.sleep(delay)
        body = r.text or ""
        status = ""
        try:
            status = (r.json() or {}).get("status", "")
        except Exception:  # noqa: BLE001
            pass
        unrestricted = status == "OK"
        sev = "high" if unrestricted else "low"
        verdict = ("UNRESTRICTED — the key answered a live Geocoding request; it is usable for "
                   "billable API abuse against the client's Google account.") if unrestricted else \
                  (f"restricted/limited (Geocoding status: {status or 'denied'}) — lower risk, but "
                   f"still rotate as it is publicly disclosed.")
        return {
            "type": "secret-impact", "name": "secret-impact", "severity": sev,
            "url": url, "method": "GET", "category": "secret-disclosure", "verified": unrestricted,
            "detail": f"disclosed Google API key {masked}: {verdict}",
            "evidence_log": [synthetic_exchange("live restriction check (Geocoding API)", method="GET",
                                                url=probe.replace(key, masked), status=r.status_code,
                                                resp_body=body[:800])],
            "repro": f"curl -s 'https://maps.googleapis.com/maps/api/geocode/json?address=test&key={masked}'",
        }
    except Exception as e:  # noqa: BLE001
        return {
            "type": "secret-impact", "name": "secret-impact", "severity": "medium",
            "url": url, "method": "GET", "category": "secret-disclosure", "verified": False,
            "detail": f"disclosed Google API key {masked}; live check failed ({e}). Rotate + restrict.",
            "evidence_log": [synthetic_exchange("disclosed Google API key", method="GET", url=url,
                                                resp_body=f"key: {masked}")],
            "repro": "# rotate + restrict in GCP console",
        }
