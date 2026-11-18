"""Discovery adapters that feed the shared frontier: feroxbuster (recursive content),
gau (historical URLs), x8 (hidden parameters). All are non-active (recon).
"""

from __future__ import annotations

import json

from ._targets import candidate_urls
from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header


def _discovery_base(url: str) -> str:
    """Origin + directory-of-path for content discovery. feroxbuster/shortscan must brute-force
    from a DIRECTORY, not a deep file URL: given https://h/home.asp they append words to the
    file path (/home.asp/WORD -> all 404) and discover nothing. Reduce to the containing
    directory (https://h/ for a root file, https://h/app/ for /app/x.asp) so discovery runs from a
    real base and recursion reaches the tree."""
    from urllib.parse import urlsplit, urlunsplit
    sp = urlsplit(url)
    path = sp.path or "/"
    base_path = path if path.endswith("/") else path.rsplit("/", 1)[0] + "/"
    if not base_path.startswith("/"):
        base_path = "/" + base_path
    return urlunsplit((sp.scheme, sp.netloc, base_path, "", ""))


def _safe_exc_note(exc: Exception) -> str:
    """Error note that NEVER leaks a cookie/token. A tool's exec error stringifies the full command
    (incl. -H 'Cookie: <session>'), which must never reach a log/report — emit only the exception
    type and, for a timeout, its duration."""
    import subprocess
    if isinstance(exc, subprocess.TimeoutExpired):
        return f"exec timeout after {int(getattr(exc, 'timeout', 0) or 0)}s"
    return f"exec error: {type(exc).__name__}"


def _calibrate_soft404_size(base: str, cookie: str = "") -> int | None:
    """Measure a soft-404 app's fixed not-found body size so feroxbuster can filter it by SIZE.

    Some legacy apps answer EVERY bogus path with HTTP 200 and a fixed-length canned page
    (a constant byte size) instead of a 404 — so status-based filtering finds nothing and real pages hide in
    the noise. Request two random non-existent paths: if BOTH return the same 2xx body size, that
    size IS the soft-404 fingerprint and we hand feroxbuster `--filter-size <N>` to discard it while
    keeping anything of a different length. If the two differ (dynamic/though-404 page, or genuine
    404s) we return None and add NO size filter — never risk filtering real responses. Read-only."""
    import secrets
    from urllib.parse import urljoin
    try:
        import httpx
    except Exception:  # noqa: BLE001
        return None
    headers = {"User-Agent": "Mozilla/5.0 (compatible; d4st-cal)"}
    if cookie:
        headers["Cookie"] = cookie
    sizes: list[int] = []
    try:
        for _ in range(2):
            probe = urljoin(base, f"d4st-no-such-{secrets.token_hex(8)}.asp")
            r = httpx.get(probe, headers=headers, timeout=15.0,
                          follow_redirects=False, verify=False)
            # Only a 2xx soft-404 is filter-by-size material; a real 3xx/4xx not-found needs no size
            # filter (feroxbuster already separates those by status).
            if r.status_code < 200 or r.status_code >= 300:
                return None
            sizes.append(len(r.content))
    except Exception:  # noqa: BLE001 - calibration must never break discovery
        return None
    if len(sizes) == 2 and sizes[0] == sizes[1] and sizes[0] > 0:
        return sizes[0]
    return None


def parse_feroxbuster(text: str) -> list[str]:
    """feroxbuster --json emits JSONL; keep response URLs with status < 400."""
    urls: list[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if o.get("type") == "response" and o.get("url"):
            status = o.get("status", 0)
            if isinstance(status, int) and 0 < status < 400:
                urls.append(o["url"])
    return urls


def parse_gau(text: str) -> list[str]:
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip().startswith("http")]


def parse_x8(text: str) -> list[dict]:
    """x8 -O json emits found parameters. Return [{url, param}]."""
    text = (text or "").strip()
    if not text:
        return []
    out: list[dict] = []
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return out
    rows = obj if isinstance(obj, list) else obj.get("results", obj.get("found", []))
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        url = r.get("url") or r.get("request_url") or ""
        for p in r.get("found_params", r.get("params", [])) or []:
            name = p.get("name") if isinstance(p, dict) else p
            if name:
                out.append({"url": url, "param": name})
    return out


@register
class FeroxbusterAdapter(ToolAdapter):
    name = "feroxbuster"
    stage = "recon"
    discovers = True
    detects = False
    active = False
    binary = "feroxbuster"

    def run(self, ctx: RunContext) -> AdapterResult:
        _base = _discovery_base(ctx.target)
        cmd = f"feroxbuster -u {_base} --json -q"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="feroxbuster not found")
        # Real-world content discovery: default to the standard SecLists common.txt (~4.7k
        # entries seen in actual engagements) so hits are legitimate, not app-tailored. Falls
        # back to raft-medium, then a small generic supplement. Override via options.
        import os
        _root = os.path.join(os.path.dirname(__file__), "..", "..", "..")
        wl = ctx.options.get("ferox_wordlist")
        if not wl:
            # Prefer a LARGER / ASP-tuned list so a legacy IIS/ASP app's deep tree is reached, then
            # fall back to the vendored common.txt. Covers both the vendored tree and a system
            # SecLists install (/usr/share/seclists). Never hard-fails on a missing list — the -w
            # flag is only added below when the chosen path actually exists.
            _sl_sys = "/usr/share/seclists/Discovery/Web-Content"
            for cand in (
                    os.path.join(_root, "vendor", "seclists", "raft-large-directories.txt"),
                    os.path.join(_root, "vendor", "seclists", "raft-large-words.txt"),
                    os.path.join(_sl_sys, "raft-large-directories.txt"),
                    os.path.join(_sl_sys, "raft-large-words.txt"),
                    os.path.join(_sl_sys, "IIS.fuzz.txt"),
                    os.path.join(_root, "vendor", "seclists", "common.txt"),
                    os.path.join(_sl_sys, "common.txt"),
                    os.path.join(_root, "vendor", "seclists", "raft-medium-directories.txt"),
                    os.path.join(os.path.dirname(__file__), "..", "..", "wordlists",
                                 "content-discovery.txt")):
                if os.path.exists(cand):
                    wl = cand
                    break
        # NB: `--json -q` emits nothing (quiet suppresses the JSON stream). `--json -o
        # /dev/stdout` routes JSONL results to stdout. feroxbuster auto-filters the SPA
        # catch-all (404-like wildcard) itself, so real resources (/ftp, /metrics) survive.
        # Recursion depth: default 3 (raised from 2) so a deep legacy IIS/ASP tree is reached;
        # D4ST_FEROX_DEPTH overrides. Extensions: probe ASP/IIS source + backup/config artefacts
        # (.asp/.aspx/.asmx/.ashx and .config/.bak/.inc/.old/.zip/.txt) so content discovery finds
        # the server-side files and leftovers a directory-only list would miss.
        _fdepth = ctx.options.get("ferox_depth") or int(os.environ.get("D4ST_FEROX_DEPTH") or 3)
        _fexts = ctx.options.get("ferox_extensions") or "asp,aspx,asmx,ashx,config,bak,inc,old,zip,txt"
        args = ["feroxbuster", "-u", _base, "--json", "-o", "/dev/stdout", "--no-state",
                "-d", str(_fdepth), "-x", str(_fexts),
                # Throttle: feroxbuster's default 50 threads DoSes fragile targets. The safe
                # profile passes ferox_threads/ferox_rate so content discovery stays gentle.
                "-t", str(ctx.options.get("ferox_threads", 10)),
                # Native adaptive safety (feroxbuster's own circuit breakers) so content
                # discovery self-protects even before the rate cap: --auto-tune lowers the scan
                # rate when it detects errors/timeouts; --auto-bail aborts if the error rate
                # spikes (target struggling). This gives feroxbuster the same detect-stress ->
                # back-off -> bail behavior the TargetHealth monitor gives the rest of the scan.
                "--auto-tune", "--auto-bail"]
        _rate = ctx.options.get("ferox_rate")
        if _rate:
            args += ["--rate-limit", str(_rate)]
        if wl and os.path.exists(os.path.expanduser(wl)):
            args += ["-w", os.path.expanduser(wl)]
        else:
            # No content-discovery corpus on the image/system. feroxbuster has no usable default
            # without -w, so it would error out — and because the convergence loop swallows adapter
            # exceptions silently, that gap was INVISIBLE (the root cause of the thin crawl: zero
            # content brute-force). Fail LOUD and skip cleanly instead of crashing the adapter; the
            # fix is to vendor raft-large (see Dockerfile) or set D4ST_FEROX_WORDLIST.
            return AdapterResult(tool=self.name, ok=False, command=cmd, discovered_urls=[],
                                 note="no content-discovery wordlist found on image/system "
                                      "(vendor raft-large, or set D4ST_FEROX_WORDLIST)")
        cookie = _cookie_header(ctx.session, ctx.target) or (ctx.options.get("cookie") or "")
        if cookie:
            args += ["-H", f"Cookie: {cookie}"]
        # NB: an explicit `--filter-similar-to <missing-path>` was tried and REVERTED — on an app
        # whose missing paths REDIRECT (301/302 to a login/notvalid page), the probe is itself a
        # redirect, so similarity-filtering wipes out the real redirect-pages too.
        # Soft-404 SIZE calibration instead: if this app answers bogus paths with a fixed-length 200
        # canned page (a constant byte size), feroxbuster's status-based view is useless — so
        # measure that length and `--filter-size` it, discarding the canned page while keeping any
        # response of a different size. Calibration returns None (adds no filter) unless TWO random
        # probes agree, so we never risk filtering real content. Opt-out: D4ST_FEROX_SOFT404=0.
        if os.environ.get("D4ST_FEROX_SOFT404", "1") != "0":
            _s404 = _calibrate_soft404_size(_base, cookie)
            if _s404:
                args += ["--filter-size", str(_s404)]
        try:
            proc = self._exec(args, timeout=ctx.options.get("timeout", 900))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=_safe_exc_note(exc))
        urls = parse_feroxbuster(proc.stdout)
        return AdapterResult(tool=self.name, ok=True, discovered_urls=urls, command=cmd,
                             note=f"{len(urls)} paths", raw=proc.stdout)


@register
class GauAdapter(ToolAdapter):
    name = "gau"
    stage = "recon"
    discovers = True
    detects = False
    active = False
    binary = "gau"

    def run(self, ctx: RunContext) -> AdapterResult:
        from urllib.parse import urlsplit
        host = urlsplit(ctx.target).hostname or ctx.target
        cmd = f"gau {host}"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="gau not found")
        try:
            proc = self._exec(["gau", "--threads", "5", host],
                              timeout=ctx.options.get("timeout", 300))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=_safe_exc_note(exc))
        urls = parse_gau(proc.stdout)
        return AdapterResult(tool=self.name, ok=True, discovered_urls=urls, command=cmd,
                             note=f"{len(urls)} historical urls", raw=proc.stdout)


@register
class X8Adapter(ToolAdapter):
    name = "x8"
    stage = "recon"
    discovers = True
    detects = False
    active = False
    binary = "x8"

    def run(self, ctx: RunContext) -> AdapterResult:
        targets = candidate_urls(ctx.seed_urls or [ctx.target], require_params=False,
                                 cap=ctx.options.get("x8_cap", 25))
        cmd = f"x8 -u <{len(targets)} urls> -O json"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="x8 not found")
        args = ["x8", "-u", *targets, "-O", "json"]
        cookie = _cookie_header(ctx.session, ctx.target)
        if cookie:
            args += ["-H", f"Cookie: {cookie}"]
        try:
            proc = self._exec(args, timeout=ctx.options.get("timeout", 900))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=_safe_exc_note(exc))
        params = parse_x8(proc.stdout)
        urls = sorted({p["url"] for p in params if p.get("url")})
        return AdapterResult(tool=self.name, ok=True, discovered_urls=urls, findings=params,
                             command=cmd, note=f"{len(params)} hidden param(s)", raw=proc.stdout)


def _with_param(url: str, param: str, value: str = "1") -> str:
    """Return `url` with `param=value` merged into its query string (existing params kept).
    Benign value; used only to make a discovered param a scannable frontier URL."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    sp = urlsplit(url)
    q = dict(parse_qsl(sp.query, keep_blank_values=True))
    if param not in q:
        q[param] = value
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(q), sp.fragment))


def parse_arjun(obj) -> list[dict]:
    """arjun -oJ writes {url: {"params": [...], "method": ..., "headers": {...}}}.
    Return [{url, param, method}] flattened. Defensive against list/older shapes."""
    out: list[dict] = []
    if isinstance(obj, dict):
        for url, info in obj.items():
            if isinstance(info, dict):
                params = info.get("params") or []
                method = info.get("method", "GET")
            else:
                params, method = (info if isinstance(info, list) else []), "GET"
            for p in params:
                name = p.get("name") if isinstance(p, dict) else p
                if name:
                    out.append({"url": url, "param": name, "method": method})
    elif isinstance(obj, list):
        for r in obj:
            if isinstance(r, dict) and r.get("url"):
                for p in r.get("params", []) or []:
                    name = p.get("name") if isinstance(p, dict) else p
                    if name:
                        out.append({"url": r["url"], "param": name,
                                    "method": r.get("method", "GET")})
    return out


# ASP-oriented hidden-parameter supplement. MERGED with arjun's bundled default list so a
# Classic-ASP/ASP.NET shop-admin app's object-id params (CatRecId, recID, custid, orderid, …) are
# probed even when they aren't in arjun's generic wordlist. The frontier gains any that the target
# actually accepts, feeding the injection + IDOR stages real params.
_ASP_PARAMS = [
    "id", "pid", "prodid", "productid", "catid", "cat", "custid", "customerid",
    "orderid", "order_id", "recid", "recID", "CatRecId", "itemType", "item",
    "itemid", "page", "uid", "userid", "sid", "docid", "fileid",
]


def _arjun_default_wordlist() -> str | None:
    """Best-effort locate arjun's bundled parameter wordlist, so :data:`_ASP_PARAMS` can be MERGED
    with it. arjun's ``-w`` REPLACES its default, so to keep the full default we must concatenate.
    Returns a path, or None (caller then keeps arjun's internal default — never a reduced list)."""
    import glob
    import os
    try:
        import importlib.util
        spec = importlib.util.find_spec("arjun")
        locs = list(getattr(spec, "submodule_search_locations", None) or []) if spec else []
        for d in locs:
            # Prefer MEDIUM (~2.5k) over LARGE (~26k): large × a full page set × --stable overruns
            # the discovery timeout (observed: arjun timed out at 1500s on 72 URLs with large,
            # discovering nothing). medium + the merged _ASP_PARAMS still covers the object-id
            # params we care about and actually FINISHES.
            for cand in ("db/medium.txt", "db/small.txt", "db/params.txt", "db/large.txt"):
                p = os.path.join(d, cand)
                if os.path.exists(p):
                    return p
    except Exception:  # noqa: BLE001
        pass
    # arjun is installed ISOLATED in its own virtualenv (so its pinned requests/urllib3 can't
    # downgrade the main interpreter's and break zaproxy/selenium — see Dockerfile), which puts its
    # package OUTSIDE the main site-packages find_spec() searches above. Cover the isolated venv
    # locations too so its bundled wordlist is still found; otherwise the adapter would fall back to
    # arjun's smaller built-in list.
    for pat in ("/usr/lib/python3*/*-packages/arjun/db/medium.txt",
                "/usr/local/lib/python3*/*-packages/arjun/db/medium.txt",
                os.path.expanduser("~/.local/lib/python3*/*-packages/arjun/db/medium.txt"),
                "/opt/arjun-venv/lib/python3*/site-packages/arjun/db/medium.txt",
                "/opt/pipx/venvs/arjun/lib/python3*/site-packages/arjun/db/medium.txt",
                "/opt/*/arjun/db/medium.txt"):
        hits = glob.glob(pat)
        if hits:
            return sorted(hits)[0]
    return None


@register
class ArjunAdapter(ToolAdapter):
    """Hidden-parameter discovery (arjun). Non-active recon: it only probes for the existence of
    accepted parameter names (differential response analysis with a junk-param baseline), never
    injects attack payloads. Complements x8 with a larger default wordlist and passive sources.
    Generic across any web stack; feeds discovered params into the frontier so downstream
    injection stages test REAL params instead of a blind wordlist.
    """
    name = "arjun"
    stage = "recon"
    discovers = True
    detects = False
    active = False          # parameter existence probing only; no attack traffic
    binary = "arjun"

    def run(self, ctx: RunContext) -> AdapterResult:
        import json
        import os
        import tempfile
        # Seed cap: cover the full crawled .asp page set, not just the first 75. Honors
        # D4ST_ARJUN_CAP (operator override), else options['arjun_cap'], else 300.
        _cap = ctx.options.get("arjun_cap")
        try:
            _cap = int(os.environ.get("D4ST_ARJUN_CAP") or _cap or 300)
        except (TypeError, ValueError):
            _cap = 300
        targets = candidate_urls(ctx.seed_urls or [ctx.target], require_params=False, cap=_cap)
        cmd = f"arjun -i <{len(targets)} urls> -oJ <out> --stable"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="arjun not found")
        if not targets:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="no targets")
        with tempfile.TemporaryDirectory() as td:
            inp = os.path.join(td, "urls.txt")
            outp = os.path.join(td, "arjun.json")
            with open(inp, "w", encoding="utf-8") as fh:
                fh.write("\n".join(targets))
            # Politeness/safety: --stable + thread and rate ceilings track the scan profile so
            # arjun can never emit more load than the engagement allows.
            workers = int(ctx.options.get("workers", 2) or 2)
            args = ["arjun", "-i", inp, "-oJ", outp, "--stable",
                    "-t", str(max(1, min(workers, 10)))]
            # MERGE the ASP param supplement with arjun's bundled default and pass it via -w. Only
            # when the default was located (merge = default ∪ ASP) — never pass a supplement-only
            # list (that would REPLACE arjun's full default and shrink coverage); if not found we
            # leave arjun on its internal default so coverage can only ever grow, never shrink.
            _wl = _arjun_default_wordlist()
            if _wl:
                _merged = os.path.join(td, "params.txt")
                try:
                    _seen: set[str] = set()
                    _lines: list[str] = []
                    with open(_wl, encoding="utf-8", errors="ignore") as _fh:
                        for _ln in _fh:
                            _w = _ln.strip()
                            if _w and _w not in _seen:
                                _seen.add(_w)
                                _lines.append(_w)
                    for _w in _ASP_PARAMS:
                        if _w not in _seen:
                            _seen.add(_w)
                            _lines.append(_w)
                    with open(_merged, "w", encoding="utf-8") as _fh:
                        _fh.write("\n".join(_lines))
                    args += ["-w", _merged]
                except Exception:  # noqa: BLE001 — fall back to arjun's internal default
                    pass
            rate = ctx.options.get("arjun_rate") or ctx.options.get("rate_limit")
            if rate:
                args += ["--rate-limit", str(int(rate))]
            delay = ctx.options.get("delay") or ctx.options.get("throttle")
            if delay:
                args += ["-d", str(delay)]
            # Carry auth so param discovery reaches the authenticated surface. Honour both the
            # session (scan stage) and options["cookie"] (discovery-loop convention).
            header_lines = []
            cookie = _cookie_header(ctx.session, ctx.target) or (ctx.options or {}).get("cookie")
            if cookie:
                header_lines.append(f"Cookie: {cookie}")
            for hk, hv in ((ctx.session or {}).get("headers") or {}).items():
                header_lines.append(f"{hk}: {hv}")
            if header_lines:
                args += ["--headers", "\n".join(header_lines)]
            try:
                # Dedicated arjun budget so param-mining can run longer than the ferox content
                # sweep without stretching ferox's own cap.
                _ato = ctx.options.get("arjun_timeout") or ctx.options.get("timeout", 1800)
                # D4ST_ARJUN_TIMEOUT (operator override) bounds the param-mine so it COMPLETES
                # within budget instead of timing out to 0 results (a hard timeout is caught below
                # and loses partial output). On a param-sparse target that has yielded 0 hidden
                # params across runs, a smaller cap + fixed budget returns cleanly rather than
                # dominating wall-clock, especially once headless crawl enlarges the frontier.
                try:
                    _ato = int(os.environ.get("D4ST_ARJUN_TIMEOUT") or _ato)
                except (TypeError, ValueError):
                    pass
                proc = self._exec(args, timeout=_ato)
            except Exception as exc:  # noqa: BLE001
                return AdapterResult(tool=self.name, ok=False, command=cmd,
                                     note=_safe_exc_note(exc))
            data = []
            if os.path.exists(outp):
                try:
                    with open(outp, encoding="utf-8") as fh:
                        data = json.load(fh)
                except Exception:  # noqa: BLE001
                    data = []
        params = parse_arjun(data)
        _ = proc  # command result kept implicitly; findings carry the params
        # Synthesise param-annotated frontier URLs so downstream scanners actually TEST the hidden
        # params (the frontier is URL-based). A benign probe value ("1") is used; real injection
        # happens later in the authorization-gated scan stage, never here.
        urls = sorted({_with_param(p["url"], p["param"]) for p in params if p.get("url")})
        return AdapterResult(tool=self.name, ok=True, discovered_urls=urls, findings=params,
                             command=cmd, note=f"{len(params)} hidden param(s)")
