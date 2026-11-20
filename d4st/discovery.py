"""Passive subdomain discovery — the recon front-end that feeds d4st's scope model.

A scan is only as good as the surface it is pointed at. An external engagement usually starts
from a bare apex domain, but the real attack surface is spread across dozens of subdomains
(``app.``, ``api.``, ``vpn.``, ``legacy.``). This module enumerates those names from passive
sources, resolves + wildcard-filters them, and lightly probes each for liveness, producing a
``DiscoveryResult`` whose live, in-scope hosts can be fed straight into ``D4ST_SCOPE_HOSTS``
(see :mod:`d4st.scope`) and seeded into a scan.

Design rules (match the rest of d4st):

* **Engine/collector only.** No AI, no telemetry, no mutation. Pure discovery.
* **Dependency-light.** Uses only what d4st already vendors (``httpx``) plus the stdlib.
  ``dnspython`` is used *if present* (for custom resolvers + CNAME records) but is NOT required —
  resolution falls back to :func:`socket.getaddrinfo`.
* **Best-effort pipeline.** Every source is independent; a source that errors or is not installed
  logs a warning and is skipped. One broken source never sinks discovery.
* **Never seed the dead.** Names that are NXDOMAIN, or resolve ONLY to the wildcard-DNS IP set,
  are dropped before anything downstream can scan them — the exact failure that poisons a scan
  frontier with ghost hosts.

The source list is a small registry of callables (:func:`register_source`) so more passive
sources can be added later without touching the pipeline.
"""

from __future__ import annotations

import os
import random
import re
import shutil
import socket
import string
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable
from urllib.parse import urlsplit

from rich.console import Console

# stderr console: warnings/progress must NEVER contaminate stdout or a --json payload.
_console = Console(stderr=True)

# Per-HTTP-request / per-probe timeout (seconds). Subprocess tools get a longer hard timeout.
DEFAULT_TIMEOUT = int(os.environ.get("D4ST_DISCOVERY_TIMEOUT", "15"))
_TOOL_TIMEOUT = int(os.environ.get("D4ST_DISCOVERY_TOOL_TIMEOUT", "120"))
DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

# Classification labels for a probed host.
LIVE = "LIVE"
REDIRECT_OFFSITE = "REDIRECT-OFFSITE"
RESOLVES_DEAD = "RESOLVES-DEAD"
NXDOMAIN = "NXDOMAIN"


def _warn(msg: str) -> None:
    """Best-effort warning to stderr (never stdout)."""
    try:
        _console.print(f"[yellow]discovery:[/yellow] {msg}")
    except Exception:  # noqa: BLE001
        try:
            sys.stderr.write(f"discovery: {msg}\n")
        except Exception:  # noqa: BLE001,S110
            pass


def _info(msg: str) -> None:
    try:
        _console.print(f"[dim]discovery:[/dim] {msg}")
    except Exception:  # noqa: BLE001,S110
        pass


# ── data model ────────────────────────────────────────────────────────────────


@dataclass
class HostRecord:
    """Everything discovery learned about one name."""
    name: str
    ips: list[str] = field(default_factory=list)
    cname: str | None = None
    resolved: bool = False
    # per-scheme liveness probes (dicts: scheme, url, status, final_url, server, title, classification)
    probes: list[dict] = field(default_factory=list)
    # coarse overall classification for the host (see LIVE / REDIRECT_OFFSITE / ...)
    classification: str = NXDOMAIN

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ips": self.ips,
            "cname": self.cname,
            "resolved": self.resolved,
            "classification": self.classification,
            "probes": self.probes,
        }


@dataclass
class DiscoveryResult:
    domain: str
    all_names: list[str] = field(default_factory=list)
    resolved: dict[str, dict] = field(default_factory=dict)   # name -> {"ips": [...], "cname": ...}
    wildcard_ips: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    records: dict[str, HostRecord] = field(default_factory=dict)
    sources_used: list[str] = field(default_factory=list)

    def _in_scope(self, host: str) -> bool:
        """A host is in-scope of the target when it is the apex or a subdomain of it."""
        host = (host or "").lower()
        return host == self.domain or host.endswith("." + self.domain)

    def to_scope_list(self) -> str:
        """Comma string of live, in-scope hosts PLUS the apex/target — the value
        ``D4ST_SCOPE_HOSTS`` understands (see :mod:`d4st.scope`).

        Dead / NXDOMAIN / wildcard-only / off-scope-redirecting hosts are excluded: they must
        never reach the scan frontier. The apex domain is always included so the operator's
        target host is in scope even if its own A record is parked.
        """
        hosts = {self.domain}
        for h in self.live_hosts:
            if self._in_scope(h):
                hosts.add(h.lower())
        return ",".join(sorted(hosts))

    def live_in_scope(self) -> list[str]:
        """The live hosts that are in-scope of the target (sorted, apex-inclusive-safe)."""
        return sorted({h.lower() for h in self.live_hosts if self._in_scope(h)})

    def summary(self) -> str:
        n_live = len(self.live_hosts)
        return (f"{self.domain}: {len(self.all_names)} names enumerated "
                f"({', '.join(self.sources_used) or 'no sources'}) · "
                f"{len(self.records)} resolved · {len(self.wildcard_ips)} wildcard IP(s) · "
                f"{n_live} live")

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "all_names": self.all_names,
            "resolved": self.resolved,
            "wildcard_ips": self.wildcard_ips,
            "live_hosts": self.live_hosts,
            "sources_used": self.sources_used,
            "records": {k: v.to_dict() for k, v in self.records.items()},
        }


# ── source registry ─────────────────────────────────────────────────────────


@dataclass
class _Source:
    name: str
    fn: Callable[..., Iterable[str]]
    deep_only: bool = False


_SOURCES: list[_Source] = []


def register_source(name: str, fn: Callable[..., Iterable[str]], *, deep_only: bool = False) -> None:
    """Register a passive enumeration source. ``fn(domain, *, timeout) -> iterable[str]``.

    Sources are best-effort: the pipeline catches exceptions and skips a failing source.
    ``deep_only`` sources run only when ``discover_subdomains(deep=True)``.
    """
    _SOURCES.append(_Source(name=name, fn=fn, deep_only=deep_only))


def _wildcards_stripped(names: Iterable[str], domain: str) -> set[str]:
    """Lowercase, strip leading ``*.``/wildcards and whitespace, and keep only the apex and its
    subdomains (a source may return unrelated SAN names from a shared cert)."""
    out: set[str] = set()
    for raw in names:
        if not raw:
            continue
        n = raw.strip().lower().rstrip(".")
        # certs often carry wildcard entries like "*.example.com" or "*.foo.example.com"
        n = re.sub(r"^\*\.", "", n)
        # drop anything that still isn't a plain hostname (spaces, schemes, emails)
        if not n or "/" in n or "@" in n or " " in n:
            continue
        if n == domain or n.endswith("." + domain):
            out.add(n)
    return out


# ── enumeration sources ───────────────────────────────────────────────────────


def _source_crtsh(domain: str, *, timeout: int = DEFAULT_TIMEOUT) -> list[str]:
    """crt.sh certificate-transparency names. Always available (pure httpx)."""
    import httpx

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        from .safety import BROWSER_UA
        ua = BROWSER_UA
    except Exception:  # noqa: BLE001
        ua = "Mozilla/5.0"
    resp = httpx.get(url, timeout=timeout, follow_redirects=True, headers={"User-Agent": ua})
    resp.raise_for_status()
    data = resp.json()
    names: list[str] = []
    for row in data:
        nv = (row.get("name_value") or "") if isinstance(row, dict) else ""
        # name_value may be newline-separated multi-SAN
        for piece in str(nv).splitlines():
            if piece.strip():
                names.append(piece.strip())
        cn = (row.get("common_name") or "") if isinstance(row, dict) else ""
        if cn.strip():
            names.append(cn.strip())
    return names


def _run_tool_lines(argv: list[str], *, timeout: int) -> list[str]:
    """Run a subprocess and return its stdout lines, or [] on any failure/timeout."""
    proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        text=True,
        check=False,
    )
    return [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]


def _source_subfinder(domain: str, *, timeout: int = _TOOL_TIMEOUT) -> list[str]:
    """subfinder (if installed). Skipped gracefully when the binary is absent."""
    if not shutil.which("subfinder"):
        _info("subfinder not on PATH — skipping (install projectdiscovery/subfinder for more coverage)")
        return []
    return _run_tool_lines(["subfinder", "-d", domain, "-all", "-silent"], timeout=timeout)


def _source_amass(domain: str, *, timeout: int = _TOOL_TIMEOUT) -> list[str]:
    """amass passive enum (deep only, if installed)."""
    if not shutil.which("amass"):
        _info("amass not on PATH — skipping (deep mode)")
        return []
    return _run_tool_lines(["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=timeout)


# Default registry. Order is informational; results are unioned.
register_source("crtsh", _source_crtsh)
register_source("subfinder", _source_subfinder)
register_source("amass", _source_amass, deep_only=True)


def _enumerate(domain: str, *, deep: bool, timeout: int) -> tuple[list[str], list[str]]:
    """Run every applicable source, union/dedup/lowercase, strip wildcards, keep only apex+subs.

    Returns ``(sorted_names, sources_that_contributed)``.
    """
    names: set[str] = set()
    used: list[str] = []
    for src in _SOURCES:
        if src.deep_only and not deep:
            continue
        try:
            raw = list(src.fn(domain, timeout=timeout))
        except Exception as e:  # noqa: BLE001 — a source must never crash the pipeline
            _warn(f"source {src.name} failed: {e}")
            continue
        cleaned = _wildcards_stripped(raw, domain)
        if cleaned:
            used.append(src.name)
            names |= cleaned
    # the apex itself is always a candidate
    names.add(domain)
    return sorted(names), used


# ── resolution + wildcard filtering ────────────────────────────────────────────


def _dnspython():
    """Return the dnspython resolver module if importable, else None (optional dependency)."""
    try:
        import dns.resolver  # noqa: F401
        return dns
    except Exception:  # noqa: BLE001
        return None


def _resolve_stdlib(name: str) -> tuple[list[str], str | None]:
    """Resolve A/AAAA via the stdlib. No custom resolvers, no CNAME (fallback path)."""
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return [], None
    except Exception:  # noqa: BLE001
        return [], None
    ips = sorted({i[4][0] for i in infos})
    return ips, None


def _resolve_dnspython(dns, name: str, resolvers: list[str] | None, timeout: int) -> tuple[list[str], str | None]:
    """Resolve A/AAAA (+ CNAME) with dnspython, honoring custom resolvers."""
    r = dns.resolver.Resolver(configure=not resolvers)
    if resolvers:
        r.nameservers = resolvers
    r.lifetime = timeout
    r.timeout = timeout
    ips: set[str] = set()
    cname: str | None = None
    for rr in ("A", "AAAA"):
        try:
            ans = r.resolve(name, rr)
            for rec in ans:
                ips.add(rec.to_text())
        except dns.resolver.NXDOMAIN:
            return [], None
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception:  # noqa: BLE001
            continue
    try:
        cans = r.resolve(name, "CNAME")
        cname = str(cans[0].target).rstrip(".").lower() if len(cans) else None
    except Exception:  # noqa: BLE001
        cname = None
    return sorted(ips), cname


def _resolver_fn(resolvers: list[str] | None, timeout: int) -> Callable[[str], tuple[list[str], str | None]]:
    """Pick the best resolution backend once and return a ``name -> (ips, cname)`` callable."""
    dns = _dnspython()
    if dns is not None:
        return lambda name: _resolve_dnspython(dns, name, resolvers, timeout)
    if resolvers:
        _info("dnspython not installed — custom resolvers ignored, using system resolver "
              "(pip install dnspython to enable --resolver + CNAME records)")
    return _resolve_stdlib


def _detect_wildcard(domain: str, resolve: Callable[[str], tuple[list[str], str | None]],
                     probes: int = 3) -> set[str]:
    """Detect wildcard DNS: resolve several random names under the domain and collect every IP
    they land on. Any real name that resolves ONLY to this set is a wildcard ghost."""
    wc: set[str] = set()
    for _ in range(probes):
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        ips, _cn = resolve(f"{rand}.{domain}")
        wc |= set(ips)
    if wc:
        _info(f"wildcard DNS detected for *.{domain}: {sorted(wc)}")
    return wc


# ── liveness probe ──────────────────────────────────────────────────────────


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _probe_host(host: str, *, timeout: int) -> list[dict]:
    """Light GET probe of http:// and https:// (80/443). No attack payloads — recon only.

    Records status, final URL, Server header, title, and a per-scheme classification. verify=off
    (self-signed is common) and redirects are followed so we see where a host really lands.
    """
    import httpx

    try:
        from .safety import BROWSER_UA
        ua = BROWSER_UA
    except Exception:  # noqa: BLE001
        ua = "Mozilla/5.0"

    out: list[dict] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        rec = {"scheme": scheme, "url": url, "status": None, "final_url": None,
               "server": None, "title": None, "classification": RESOLVES_DEAD}
        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=timeout,
                              headers={"User-Agent": ua}) as client:
                resp = client.get(url)
            rec["status"] = resp.status_code
            rec["final_url"] = str(resp.url)
            rec["server"] = resp.headers.get("server")
            body = resp.text[:20000] if resp.content else ""
            m = _TITLE_RE.search(body or "")
            if m:
                rec["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
            final_host = (urlsplit(str(resp.url)).hostname or "").lower()
            if final_host and (final_host == host or final_host.endswith("." + host)
                               or host.endswith("." + final_host) or _same_reg_domain(final_host, host)):
                rec["classification"] = LIVE
            else:
                rec["classification"] = REDIRECT_OFFSITE
        except Exception as e:  # noqa: BLE001 — a dead scheme is expected, not an error
            rec["classification"] = RESOLVES_DEAD
            rec["error"] = str(e)[:200]
        out.append(rec)
    return out


def _same_reg_domain(a: str, b: str) -> bool:
    """Coarse 'same registrable domain' check (last two labels). Keeps a www<->apex or
    sub<->sibling redirect classified LIVE instead of REDIRECT-OFFSITE."""
    ta, tb = a.split("."), b.split(".")
    return len(ta) >= 2 and len(tb) >= 2 and ta[-2:] == tb[-2:]


def _classify(probes: list[dict]) -> str:
    labels = {p["classification"] for p in probes}
    if LIVE in labels:
        return LIVE
    if REDIRECT_OFFSITE in labels:
        return REDIRECT_OFFSITE
    return RESOLVES_DEAD


# ── pipeline ──────────────────────────────────────────────────────────────────


def discover_subdomains(domain: str, *, deep: bool = False, resolvers: list[str] | None = None,
                        timeout: int = DEFAULT_TIMEOUT, probe: bool = True) -> DiscoveryResult:
    """Enumerate, resolve + wildcard-filter, and (optionally) liveness-probe subdomains of
    ``domain``. Returns a :class:`DiscoveryResult`.

    Args:
        domain: apex domain (bare, e.g. ``example.com``; a URL/host is normalized to its apex-ish host).
        deep: also run deep-only sources (amass) if their binaries are installed.
        resolvers: custom DNS resolvers (used only when dnspython is installed; default 1.1.1.1/8.8.8.8).
        timeout: per-request/per-probe timeout in seconds.
        probe: run the liveness probe (set False to only enumerate+resolve).
    """
    domain = _normalize_domain(domain)
    if resolvers is None:
        resolvers = list(DEFAULT_RESOLVERS)

    result = DiscoveryResult(domain=domain)

    # a. ENUMERATE
    names, used = _enumerate(domain, deep=deep, timeout=timeout)
    result.all_names = names
    result.sources_used = used
    _info(f"enumerated {len(names)} candidate name(s) from: {', '.join(used) or 'none'}")

    # b. RESOLVE + WILDCARD-FILTER
    resolve = _resolver_fn(resolvers, timeout)
    wildcard_ips = _detect_wildcard(domain, resolve)
    result.wildcard_ips = sorted(wildcard_ips)

    for name in names:
        ips, cname = resolve(name)
        rec = HostRecord(name=name, ips=ips, cname=cname, resolved=bool(ips or cname))
        if not ips and not cname:
            rec.classification = NXDOMAIN
            result.records[name] = rec
            continue
        # drop names that resolve ONLY to the wildcard set (ghosts) — unless they have a real CNAME
        if ips and not cname and wildcard_ips and set(ips) <= wildcard_ips:
            rec.classification = RESOLVES_DEAD  # wildcard-only; not worth scanning
            rec._wildcard_only = True  # type: ignore[attr-defined]
            result.records[name] = rec
            continue
        result.resolved[name] = {"ips": ips, "cname": cname}
        rec.classification = RESOLVES_DEAD  # provisional until probed
        result.records[name] = rec

    # c. LIVENESS PROBE
    if probe:
        for name, rec in result.records.items():
            if name not in result.resolved:
                continue  # NXDOMAIN / wildcard-only are never probed or seeded
            rec.probes = _probe_host(name, timeout=timeout)
            rec.classification = _classify(rec.probes)
    else:
        # no probe: treat everything that resolved (and isn't wildcard-only) as live surface
        for name in result.resolved:
            result.records[name].classification = LIVE

    result.live_hosts = sorted(n for n, r in result.records.items() if r.classification == LIVE)
    _info(result.summary())
    return result


def _normalize_domain(raw: str) -> str:
    """Accept a URL, host:port, or bare domain and return the lowercased host."""
    raw = (raw or "").strip().lower()
    if "://" in raw:
        raw = urlsplit(raw).hostname or raw
    else:
        raw = raw.split("/")[0]
    if ":" in raw:
        raw = raw.split(":")[0]
    return raw.strip(".")
