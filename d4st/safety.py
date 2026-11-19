"""Scan safety: politeness (rate limiting), auth-endpoint exclusion, and lockout/WAF
detect-and-back-off. Scanning authenticated production apps can trip account lockouts,
rate limits, and WAF blocks; this module keeps the engagement from harming the target.

The golden rules encoded here:
- Never actively test the login/logout/reset endpoints (that locks accounts).
- Never re-authenticate mid-scan; reuse one session (enforced in the engagement flow).
- Throttle requests to a configured rate.
- Watch responses for lockout/WAF signals and back off (or halt) instead of hammering.
"""

from __future__ import annotations

import fnmatch
import os
import posixpath
import re
import time
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

# URL patterns we must NOT actively test (submitting payloads/failed logins here locks
# accounts or logs the scanner out).
_AUTH_PATH = re.compile(
    r"(login|logon|signin|sign-in|logout|signout|sign-out|auth|authenticate|"
    r"password|passwd|reset|forgot|register|signup|sign-up|sso|oauth|saml)",
    re.IGNORECASE,
)


def is_auth_endpoint(url: str) -> bool:
    return bool(_AUTH_PATH.search(urlsplit(url).path))


# Session-DESTROYING endpoints. Following one of these (even a plain GET during discovery)
# logs the scanner out and blinds the rest of the authenticated crawl. This is deliberately
# NARROWER than is_auth_endpoint: discovery may and should still traverse authenticated
# content areas whose path merely contains an auth-ish word (e.g. /Authorization/,
# /PasswordVault/, /AuthorList/, /Registers/). The broad is_auth_endpoint stays in force at
# the ACTIVE-TEST gate (never fuzz a login/reset endpoint -> no account lockouts); this one
# governs only what a GET-based crawler is allowed to follow.
_LOGOUT_PATH = re.compile(
    r"(logout|log-out|logoff|log-off|signout|sign-out|signoff|sign-off|"
    r"(?:^|[/_-])exit(?:$|[/_-]))",
    re.IGNORECASE,
)


def is_session_destroying_endpoint(url: str) -> bool:
    """True only for logout / sign-out style links a crawler must never follow."""
    return bool(_LOGOUT_PATH.search(urlsplit(url).path))


# A realistic desktop-browser User-Agent. Non-browser UAs (python-httpx, d4st-*, curl) are widely
# tarpitted or blocked by CDN/WAF stacks (GoDaddy DPS, Cloudflare, Akamai) — that silently zeroes a
# scan against a protected site. Authorized engagements allow-list the source IP, not the UA, so
# presenting a browser UA is both safe and necessary for coverage parity with a real browser/Burp.
# Override via D4ST_USER_AGENT.
import os as _os

BROWSER_UA = _os.environ.get(
    "D4ST_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
)


def browser_headers(extra: dict | None = None) -> dict:
    """Default request headers carrying a realistic browser User-Agent + Accept, so WAFs don't
    tarpit/deny the scanner. `extra` is merged on top (e.g. Cookie/Authorization)."""
    h = {
        "User-Agent": BROWSER_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if extra:
        h.update(extra)
    return h


# Query params that carry credentials / auth secrets — testing these submits or manipulates
# authentication and is never safe on an auth endpoint.
_CRED_PARAMS = frozenset({
    "username", "user", "uname", "usr", "login", "logon", "email", "mail",
    "pass", "password", "passwd", "pwd", "otp", "mfa", "code", "pin", "token", "secret",
})


def auth_endpoint_safe_to_test(url: str, method: str = "GET", params=None) -> bool:
    """An auth endpoint is safe to actively (read-only GET) test ONLY when it is a GET whose query
    params are ALL non-credential — e.g. a return-URL / nav param like ?url= / ?returnUrl= / ?reason=
    on a login page (OWA `logon.aspx?url=...`). Those are real reflected-injection points and testing
    them neither submits credentials nor triggers a login/logout. Anything with a credential-like
    param, no params, or a non-GET method stays blocked (account-lockout / session-kill protection)."""
    if (method or "GET").upper() != "GET":
        return False
    params = params or []
    if not params:
        return False
    return not any((p or "").lower() in _CRED_PARAMS for p in params)


# ============================================================================================
# OPERATOR-CONFIGURABLE PATH EXCLUSION (D4ST_EXCLUDE_PATHS) — the safety-critical scope carve-out.
#
# Motivation: some target apps expose endpoints whose MERE INVOCATION causes real-world external
# side effects — e.g. an archiving app where "create capture / create site / start crawl / archive"
# makes the SERVER fetch an arbitrary external URL on our behalf. Fuzzing (or even benignly
# auto-submitting) those endpoints is harmful no matter how aggressive the engagement is. This
# matcher lets an operator name those paths and PROVABLY keep the scanner from sending any
# intrusive / state-changing / form-submitting request to them — while plain GET discovery (crawl
# + sitemap listing) of the same paths is still allowed, so they remain mapped in the report.
#
# The exclusion WINS over everything: it is independent of the policy name (even `aggressive`) and
# of fuzz_forms. An empty / unset env is exactly today's behavior (no regression).
#
# PATTERN FORMAT (D4ST_EXCLUDE_PATHS): a comma-separated list; each item is matched against the
# URL *path AND query string* (case-insensitively — so a router that dispatches on ``?do=capture``
# is covered) in one of three ways:
#   * ``re:<regex>``  — a Python regex, applied with re.search (matches anywhere in path+query).
#   * a glob with ``*`` / ``?`` / ``[seq]`` metacharacters — matched against path+query with fnmatch
#     (e.g. ``/api/*/capture*`` matches /api/v2/capture, ``*capture*`` matches anything with capture).
#   * a plain string (no metacharacters) — matched as a case-insensitive SUBSTRING of path+query
#     (e.g. ``/capture`` matches /api/v2/capture/new; ``do=capture`` matches ?do=capture). Chosen to
#     over-match rather than under-match: this is a safety gate, so a miss leaks an intrusive
#     request while a false include only declines to attack a path.
# Matching is done against SEVERAL normalized views of the URL so encoding tricks cannot slip past:
# the raw path+query, the PERCENT-DECODED path+query (so ``/api%2Fcapture`` is caught), and the
# dot-segment-collapsed decoded path. Any view matching any pattern = excluded.
#
# FAIL-CLOSED: if D4ST_EXCLUDE_PATHS is set and ANY ``re:`` pattern fails to compile, construction
# RAISES ExcludeConfigError — the run must ABORT with a clear error rather than silently drop the
# bad pattern and run with the intended paths fully attackable. A typo halts; it never disables.


class ExcludeConfigError(ValueError):
    """Raised when D4ST_EXCLUDE_PATHS contains an uncompilable pattern — the run must fail closed."""


class ExcludedPathError(Exception):
    """Raised by the guarded-send chokepoint when a caller tries to send to an excluded path."""

    def __init__(self, url: str, method: str = ""):
        self.url = url
        self.method = method
        super().__init__(f"refused excluded request: {method} {url}".strip())


class ExcludePathMatcher:
    """Compiled D4ST_EXCLUDE_PATHS matcher. Cheap to query (precompiled); ``bool(matcher)`` is
    False when no patterns are configured so callers can skip the check entirely (zero overhead /
    zero behavior change when the env is unset). Matches on path AND query, over several normalized
    views (raw / percent-decoded / dot-collapsed). Fails closed on an uncompilable ``re:`` pattern."""

    def __init__(self, raw: str | None = ""):
        self.raw = raw or ""
        self.patterns: list[str] = [p.strip() for p in self.raw.split(",") if p.strip()]
        self._substrings: list[str] = []
        self._globs: list[str] = []
        self._regexes: list[re.Pattern] = []
        for item in self.patterns:
            if item.lower().startswith("re:"):
                try:
                    self._regexes.append(re.compile(item[3:], re.IGNORECASE))
                except re.error as exc:
                    # FAIL-CLOSED: a bad regex must abort the run, never silently run unprotected.
                    raise ExcludeConfigError(
                        f"D4ST_EXCLUDE_PATHS: invalid regex pattern {item!r}: {exc}. Refusing to "
                        f"run (fail-closed) so the intended paths are not left attackable — fix the "
                        f"pattern or remove it.") from exc
            elif any(c in item for c in "*?["):
                self._globs.append(item.lower())
            else:
                self._substrings.append(item.lower())

    def __bool__(self) -> bool:
        return bool(self._substrings or self._globs or self._regexes)

    @staticmethod
    def _views(url: str) -> list[str]:
        """Normalized path+query views of `url` to match against — raw, percent-decoded, and the
        dot-segment-collapsed decoded path. Over-match on purpose (safety gate)."""
        try:
            sp = urlsplit(url or "")
            raw_path = sp.path or (url or "")
            raw_pq = raw_path + (("?" + sp.query) if sp.query else "")
            dec_path = unquote(raw_path)
            dec_pq = unquote(raw_pq)
            # collapse ./ and ../ in the decoded path so /a/../capture can't hide the segment
            try:
                norm = posixpath.normpath(dec_path)
            except Exception:  # noqa: BLE001
                norm = dec_path
            return list({raw_path, raw_pq, dec_path, dec_pq, norm})
        except Exception:  # noqa: BLE001 - never let a weird URL crash the safety gate
            return [url or ""]

    def matches(self, url: str) -> bool:
        """True if ANY normalized view of the URL (path+query) matches ANY exclude pattern."""
        if not self:
            return False
        views = self._views(url)
        lows = [v.lower() for v in views]
        for s in self._substrings:
            if any(s in v for v in lows):
                return True
        for g in self._globs:
            if any(fnmatch.fnmatch(v, g) for v in lows):
                return True
        for rx in self._regexes:
            if any(rx.search(v) for v in views):
                return True
        return False

    def zap_exclude_regexes(self) -> list[str]:
        """Render the patterns as ZAP Automation-Framework ``excludePaths`` entries (quoted regexes
        that ZAP matches against the FULL URL). Globs/substrings become ``'.*<escaped>.*'``; a
        ``re:`` pattern is passed through wrapped in ``'.*(...).* '``-style anchoring-free form so it
        matches anywhere in the URL, mirroring our own .matches() semantics."""
        out: list[str] = []
        for item in self.patterns:
            if item.lower().startswith("re:"):
                body = item[3:]
                try:
                    re.compile(body)
                except re.error:
                    continue
                out.append(f"'.*(?:{body}).*'")
            else:
                # strip glob metachars to a literal core, then escape for regex, wildcard both ends
                core = re.escape(item.replace("*", "").replace("?", ""))
                out.append(f"'.*{core}.*'")
        return out


# Module-level ACTIVE matcher consulted by is_write_action / is_state_changing (which take no
# policy argument). get_policy() rebuilds it from the current environment and installs it here, so
# every component that calls those free functions honors the same carve-out. Tests can install one
# directly via set_exclude_matcher().
_ACTIVE_EXCLUDE = ExcludePathMatcher(os.environ.get("D4ST_EXCLUDE_PATHS", ""))


def get_exclude_matcher() -> ExcludePathMatcher:
    """The currently-installed D4ST_EXCLUDE_PATHS matcher."""
    return _ACTIVE_EXCLUDE


def set_exclude_matcher(matcher_or_raw) -> ExcludePathMatcher:
    """Install a matcher (an ExcludePathMatcher, or a raw pattern string) as the active one."""
    global _ACTIVE_EXCLUDE
    _ACTIVE_EXCLUDE = (matcher_or_raw if isinstance(matcher_or_raw, ExcludePathMatcher)
                       else ExcludePathMatcher(matcher_or_raw))
    return _ACTIVE_EXCLUDE


def reload_exclude_matcher_from_env() -> ExcludePathMatcher:
    """Rebuild + install the active matcher from D4ST_EXCLUDE_PATHS.

    If the env var is PRESENT (even empty) it is authoritative and installed. If it is ABSENT, the
    currently-active matcher is KEPT — so a matcher installed programmatically via Config/
    set_exclude_matcher is never silently wiped by an env-less call (single source of truth, no
    latent fail-open). Raises ExcludeConfigError if a configured pattern is uncompilable."""
    raw = os.environ.get("D4ST_EXCLUDE_PATHS")
    if raw is None:
        return _ACTIVE_EXCLUDE
    return set_exclude_matcher(raw)


def is_path_excluded(url: str) -> bool:
    """True if `url`'s path/query matches the active D4ST_EXCLUDE_PATHS carve-out."""
    return _ACTIVE_EXCLUDE.matches(url)


# ---- guarded-send chokepoint: the single backstop every active/intrusive dispatcher routes through.
def is_excluded_send(url: str) -> bool:
    """True if sending an ACTIVE/intrusive request to `url` is forbidden by the carve-out. Blocks
    ALL methods including a parameterized GET (a GET to a side-effecting capture endpoint still
    fires the side effect). Passive discovery crawlers must NOT use this (they may plain-GET
    excluded paths so they appear in the sitemap); it is only for attack/mutation sends."""
    return _ACTIVE_EXCLUDE.matches(url)


def assert_not_excluded(url: str, method: str = "GET") -> None:
    """Chokepoint for callers that send one request at a time: refuse (loud log + raise
    ExcludedPathError) when `url` is excluded. Fail-closed for intrusive senders."""
    if _ACTIVE_EXCLUDE.matches(url):
        print(f"[safety] EXCLUDED {(method or 'GET').upper()} {urlsplit(url).path} — matched "
              f"D4ST_EXCLUDE_PATHS (refused by guarded-send chokepoint)", flush=True)
        raise ExcludedPathError(url, method)


def filter_excluded(urls, *, label: str = "active testing") -> list:
    """Drop every excluded URL from an active/intrusive frontier, logging each withheld path. The
    standard way an intrusive dispatcher sanitizes an incoming URL list (backstop even when the
    caller already filtered). No-op (returns a list copy) when no carve-out is configured."""
    if not _ACTIVE_EXCLUDE:
        return list(urls)
    out = []
    for u in urls:
        if _ACTIVE_EXCLUDE.matches(u):
            print(f"[safety] EXCLUDED {urlsplit(u).path} — matched D4ST_EXCLUDE_PATHS "
                  f"(withheld from {label})", flush=True)
        else:
            out.append(u)
    return out


# URL patterns that perform DESTRUCTIVE or NOTIFYING actions. Actively fuzzing these on real
# infra can delete data, spam real inboxes/phones, move money, or fire irreversible workflows.
# Deliberately does NOT include create/update/edit/save (too common, and injection often lives
# there) — only the clearly-harmful verbs, so recall loss stays minimal.
_STATE_CHANGING = re.compile(
    r"(delete|remove|destroy|drop|purge|erase|wipe|"
    r"send|email|mail|sms|notify|invite|"
    r"approve|reject|confirm|checkout|purchase|order|payment|\bpay\b|transfer|withdraw|deposit|refund|"
    r"discharge|deactivate|disable|revoke|suspend|terminate|cancel|"
    r"reset|restore|rollback|migrate|import|export|backup)",
    re.IGNORECASE,
)


def is_state_changing(url: str) -> bool:
    """True if the URL path looks like a destructive/notifying action (fuzz it only when the
    policy allows). Checks path only, so a benign ?q=... query is not misclassified.

    NOTE: path-only / method-agnostic. For the ACTIVE-TEST exclusion gate prefer the
    method-aware :func:`is_write_action`, which does not drop a GET read whose path merely
    mentions a verb (e.g. ``OrderDetail.asp?id=`` / ``OrderList.asp``)."""
    # D4ST_EXCLUDE_PATHS carve-out WINS: an operator-excluded path is treated as state-changing
    # everywhere this gate is consulted (replay / proxy / sweep write-replay all skip it), so the
    # scanner never re-issues a mutating request to it, under any policy.
    if _ACTIVE_EXCLUDE.matches(url):
        return True
    return bool(_STATE_CHANGING.search(urlsplit(url).path))


def is_write_action(url: str, method: str = "GET") -> bool:
    """Method-aware destructive-action gate for the ACTIVE-TEST exclusion filter.

    A request is a genuine state-changing WRITE — and so excluded from active fuzzing — ONLY
    when BOTH hold:
      * the method is non-GET (POST/PUT/PATCH/DELETE), AND
      * the path/action carries a destructive/notifying verb (:data:`_STATE_CHANGING`).

    A GET is a READ even when its path contains a verb like ``order``/``export``/``confirm``/
    ``cancel`` (``OrderDetail.asp?id=`` reads one order; it does not place/cancel it), so a GET
    STAYS in active testing. This fixes the surface-starvation bug where every GET whose path
    merely mentioned a verb was dropped from injection/IDOR testing.

    Genuine writes (a POST/PUT/PATCH/DELETE to a destructive path — ConfirmOrder / SendMail /
    DeleteItem / checkout / payment) are still excluded so the scanner never fuzzes them.

    ``is_state_changing(url)`` is kept for callers that have no method (and for back-compat);
    this is the preferred gate wherever a method is available."""
    # D4ST_EXCLUDE_PATHS carve-out WINS over everything (policy name, fuzz_forms, method): an
    # operator-excluded path is NEVER actionable for active/write testing, so it is reported as a
    # write action here regardless of method. This drops it from the injection feed
    # (_materialize_url) and the active-target filter even under the `aggressive` policy. Plain GET
    # discovery / sitemap listing does not go through this gate, so excluded paths are still mapped.
    if _ACTIVE_EXCLUDE.matches(url):
        return True
    if (method or "GET").upper() == "GET":
        return False
    return bool(_STATE_CHANGING.search(urlsplit(url).path))


# Response signals that we are being rate-limited / locked out / WAF-blocked.
_LOCKOUT_TEXT = re.compile(
    r"account (is )?locked|too many (attempts|requests|failed)|temporarily (locked|blocked|"
    r"disabled)|rate.?limit|access denied|request blocked|has been blocked|try again later|"
    r"unusual activity|captcha",
    re.IGNORECASE,
)


@dataclass
class Politeness:
    """Rate-limit config + a token-bucket-ish throttle. Also renders tool flags."""
    rps: float = 5.0            # requests per second ceiling (per worker)
    concurrency: int = 5
    delay_ms: int = 0           # extra fixed delay between requests
    _last: float = 0.0

    def wait(self) -> None:
        """Block just enough to honor the rate limit. Uses a monotonic clock (never new Date)."""
        min_interval = (1.0 / self.rps) if self.rps > 0 else 0.0
        min_interval += self.delay_ms / 1000.0
        now = time.monotonic()
        gap = now - self._last
        if gap < min_interval:
            time.sleep(min_interval - gap)
        self._last = time.monotonic()

    # tool-specific throttle flags
    def katana_flags(self) -> list[str]:
        f = ["-c", str(self.concurrency)]
        if self.rps > 0:
            f += ["-rl", str(int(self.rps))]
        # katana's -delay takes INTEGER SECONDS, not "250ms" (that errors out and kills the
        # crawl -> 0 urls). The -rl rate-limit is the real throttle; only add -delay for
        # whole-second delays.
        if self.delay_ms >= 1000:
            f += ["-delay", str(self.delay_ms // 1000)]
        return f

    def nuclei_flags(self) -> list[str]:
        f = ["-c", str(self.concurrency)]
        if self.rps > 0:
            f += ["-rl", str(int(self.rps))]
        return f

    def sqlmap_flags(self) -> list[str]:
        f = ["--threads", str(min(self.concurrency, 5))]
        if self.delay_ms:
            f += ["--delay", str(self.delay_ms / 1000.0)]
        return f


class AdaptiveThrottle:
    """A live, per-request backoff governor. TargetHealth pings BETWEEN stages; this reacts INSIDE
    a stage: when the server answers 429 (rate-limited) or 503 (overloaded), the inter-request delay
    doubles (up to a cap); a run of healthy 2xx/3xx/4xx responses lets it decay back toward the base.
    Strictly protective — it only ever SLOWS the scan, never speeds it past the base delay. Shared
    across the active depth stages so they collectively ease off a straining target.

    Usage:  t = AdaptiveThrottle(base_delay=0.15)
            t.wait(); r = client.get(u); t.record(r.status_code)
    """

    def __init__(self, base_delay: float = 0.15, cap: float = 5.0, on_backoff=None):
        self.base = max(0.0, float(base_delay))
        self.delay = self.base
        self.cap = float(cap)
        self.backoffs = 0
        self._healthy_streak = 0
        self._on_backoff = on_backoff   # optional callback(status, new_delay) for logging

    def record(self, status: int | None) -> None:
        if status in (429, 503):
            self.delay = min(self.cap, max(self.base, self.delay) * 2 or 0.25)
            self.backoffs += 1
            self._healthy_streak = 0
            if self._on_backoff:
                try:
                    self._on_backoff(status, self.delay)
                except Exception:  # noqa: BLE001
                    pass
        else:
            # decay: after several clean responses, relax one step toward the base delay
            self._healthy_streak += 1
            if self._healthy_streak >= 5 and self.delay > self.base:
                self.delay = max(self.base, self.delay / 2)
                self._healthy_streak = 0

    def wait(self) -> None:
        if self.delay > 0:
            time.sleep(self.delay)


def pace(throttle, delay: float, status: int | None = None) -> None:
    """Uniform inter-request pacing for the active depth stages. With a shared AdaptiveThrottle it
    records the just-seen status (backing off on 429/503) and waits its adaptive delay; without one
    it falls back to a fixed sleep. Lets every module pace identically with one call."""
    if throttle is not None:
        throttle.record(status)
        throttle.wait()
    elif delay:
        time.sleep(delay)


# Named profiles.
POLITE = Politeness(rps=2.0, concurrency=2, delay_ms=250)      # fragile / lockout-prone infra
ENGAGEMENT = Politeness(rps=12.0, concurrency=6, delay_ms=0)   # normal engagement (bounded parallel)
NORMAL = Politeness(rps=8.0, concurrency=8, delay_ms=0)        # test env
AGGRESSIVE = Politeness(rps=25.0, concurrency=20, delay_ms=0)  # owned lab, allowlisted

PROFILES = {"polite": POLITE, "engagement": ENGAGEMENT, "normal": NORMAL,
            "aggressive": AGGRESSIVE}


@dataclass
class ScanPolicy:
    """Bundle of every safety knob for one engagement, selected by name. Wraps a Politeness
    profile plus the policy decisions that determine how destructive the scan can be. This is
    the single flag that makes a scan production-safe instead of something-you-remember-to-set.
    """
    name: str
    politeness: Politeness
    active_scan: bool = True          # emit attack traffic at all (False = read-only recon)
    fuzz_forms: bool = True           # submit/mutate via POST forms + stored-XSS + auto-form-fill
    skip_state_changing: bool = False  # skip fuzzing delete/send/pay/... endpoints
    sqlmap_level: int = 3
    sqlmap_risk: int = 2
    sqlmap_technique: str = "BEUST"   # B/E/U/S/T; drop T,S on safe (no time-hang / no stacked)
    lfi_deep: bool = True             # allow the huge Traversal.txt corpus (heavy)
    oast_selfhosted_only: bool = False  # never use public interactsh (no data leaves the net)
    # Operator path-exclusion carve-out (D4ST_EXCLUDE_PATHS). Populated by get_policy() from the
    # environment. Independent of every other knob here — a matching path is skipped by ALL
    # intrusive testing even under `aggressive` / fuzz_forms=True. Default: empty (no exclusion).
    exclude_paths: ExcludePathMatcher = field(default_factory=lambda: ExcludePathMatcher(""))

    def sqlmap_args(self) -> list[str]:
        return ["--level", str(self.sqlmap_level), "--risk", str(self.sqlmap_risk),
                f"--technique={self.sqlmap_technique}"]


# Named policies. 'engagement' is THE default: a normal professional-engagement posture that
# finishes in hours, not days. Safety and speed are orthogonal here — it keeps the FULL safe
# contract (never fuzz destructive/notifying or auth endpoints, no data-mutating writes beyond
# form fuzzing, error/union/boolean sqlmap only, OAST in-network, adaptive halt on target
# stress) and gets its speed from BOUNDED parallelism (per-URL tools fan out to the concurrency
# ceiling) plus dropping the artificial per-request delay floor. 'safe-deep' is the same depth
# at a gentler single-stream throttle — the right choice for fragile/legacy targets (e.g. EHR).
POLICIES: dict[str, ScanPolicy] = {
    # Default: fast-but-safe. Bounded parallelism (concurrency 6) + full depth + full safety.
    "engagement": ScanPolicy(
        name="engagement", politeness=ENGAGEMENT, active_scan=True, fuzz_forms=True,
        skip_state_changing=True,          # never fuzz delete/send/pay/... endpoints
        sqlmap_level=5, sqlmap_risk=1,     # max coverage, safe payloads only (same as safe-deep)
        sqlmap_technique="BEU",            # boolean/error/union: no time-hang, no stacked writes
        lfi_deep=True, oast_selfhosted_only=True),
    # Same depth + safety as engagement but a gentle single-stream throttle (concurrency 2) for
    # fragile/lockout-prone targets where even bounded parallelism is too much.
    "safe-deep": ScanPolicy(
        name="safe-deep", politeness=POLITE, active_scan=True, fuzz_forms=True,
        skip_state_changing=True,          # never fuzz delete/send/pay/... endpoints
        sqlmap_level=5, sqlmap_risk=1,     # max coverage, safe payloads only
        sqlmap_technique="BEU",            # boolean/error/union: no time-hang, no stacked writes
        lfi_deep=True, oast_selfhosted_only=True),
    # Live/client infra (esp. healthcare/EHR): throttle hard, no data mutation, no destructive
    # or notifying endpoints, error/union/boolean SQLi only (no time-hang or stacked queries),
    # OAST must stay in-network. Detection breadth (crawl reach, LFI/XSS payloads, verify layer)
    # is UNAFFECTED — only injection depth + write actions are constrained.
    "production-safe": ScanPolicy(
        name="production-safe", politeness=POLITE, active_scan=True, fuzz_forms=False,
        skip_state_changing=True, sqlmap_level=2, sqlmap_risk=1, sqlmap_technique="BEU",
        lfi_deep=False, oast_selfhosted_only=True),
    # Read-only recon: no attack traffic whatsoever (crawl/TLS/headers/config/JS only).
    "passive-only": ScanPolicy(
        name="passive-only", politeness=POLITE, active_scan=False, fuzz_forms=False,
        skip_state_changing=True, sqlmap_level=1, sqlmap_risk=1, sqlmap_technique="B",
        lfi_deep=False, oast_selfhosted_only=True),
    # Test/staging: full depth, disposable target.
    "staging": ScanPolicy(
        name="staging", politeness=NORMAL, active_scan=True, fuzz_forms=True,
        skip_state_changing=False, sqlmap_level=3, sqlmap_risk=2, lfi_deep=True),
    # Owned lab, allowlisted: max aggression.
    "aggressive": ScanPolicy(
        name="aggressive", politeness=AGGRESSIVE, active_scan=True, fuzz_forms=True,
        skip_state_changing=False, sqlmap_level=3, sqlmap_risk=3, lfi_deep=True),
}
# Back-compat aliases for the old politeness-only profile names.
POLICIES["polite"] = POLICIES["production-safe"]
POLICIES["normal"] = POLICIES["staging"]


def get_policy(name: str) -> ScanPolicy:
    """Return the named policy with the D4ST_EXCLUDE_PATHS carve-out applied.

    The matcher is built fresh from the current environment, installed as the module-active matcher
    (so the policy-less free functions is_write_action / is_state_changing honor it too), and
    attached to a COPY of the named policy via :func:`dataclasses.replace` — never mutating the
    shared POLICIES entry. An empty/unset env yields an empty matcher: behavior is exactly as
    before (no regression)."""
    import dataclasses
    base = POLICIES.get(name, POLICIES["engagement"])
    matcher = reload_exclude_matcher_from_env()
    return dataclasses.replace(base, exclude_paths=matcher)


@dataclass
class TargetHealth:
    """Adaptive stress monitor that keeps safe-deep a SINGLE profile which self-throttles
    instead of DoSing a fragile target. Between heavy stages it actively pings the target and
    escalates a stress stage: 0 = full depth (sqlmap L5), 1 = reduced depth (cap at L3),
    2 = halt active scanning. A robust target stays at stage 0 and gets full depth; a target
    that starts failing (connection refused / 5xx / very slow) is stepped down, then the scan
    halts gracefully with whatever it found rather than grinding for hours against a corpse.

    Strikes are weighted: a hard failure (down/5xx) counts double a slow response, and a
    healthy ping decays one strike (recovery). >=2 strikes -> reduce depth; >=4 -> halt."""
    base_url: str
    cookie: str = ""
    slow_ms: float = 6000.0
    # ping_timeout RAISED 10s -> 25s. v3 post-mortem: a legacy app that merely got SLOW (its response
    # blew past a 10s deadline) threw a timeout and was scored a DOUBLE-weight "dead" hard-fail (+2)
    # instead of a single "slow" strike (+1) — 2 such pings HALTed the gate and silently skipped ZAP +
    # deep injection. With a 25s deadline a 6-25s response now actually returns and is scored +1 slow.
    ping_timeout: float = 25.0
    confirm_delay: float = 6.0       # a failed ping is RE-probed after this pause; only a confirmed fail is hard
    stage: int = 0
    strikes: int = 0
    pings: int = 0
    events: list = field(default_factory=list)

    def ping(self) -> tuple[bool, float, str]:
        """Active liveness GET on the base URL. Returns (alive, elapsed_ms, reason). alive is False
        on connection error / timeout / any 5xx. reason in {ok,slow,5xx,timeout,error} so a
        post-mortem can tell a genuinely-dead target apart from a merely-slow one (the v3 gap:
        both failure modes were logged identically as "unresponsive/5xx")."""
        import httpx
        # verify=False: an invalid/self-signed cert (routine in pentests) must NOT read as "down".
        # browser UA so a WAF doesn't tarpit the liveness ping either.
        headers = browser_headers({"Cookie": self.cookie} if self.cookie else None)
        t0 = time.monotonic()
        try:
            r = httpx.get(self.base_url, headers=headers, timeout=self.ping_timeout,
                          follow_redirects=True, verify=False)
            el = (time.monotonic() - t0) * 1000.0
            if r.status_code >= 500:
                return (False, el, "5xx")
            return (True, el, "slow" if el > self.slow_ms else "ok")
        except Exception as exc:  # noqa: BLE001 - any failure = not alive
            el = (time.monotonic() - t0) * 1000.0
            reason = "timeout" if isinstance(exc, httpx.TimeoutException) else "error"
            return (False, el, reason)

    def check(self) -> int:
        """Ping and update the stress stage. Returns the current stage (0/1/2). Once halted it stays
        halted UNLESS recover_check() later proves the target came back (used before the heaviest
        engine). A failed ping is CONFIRMED by an immediate re-probe before counting as a hard fail,
        so two unlucky liveness blips can no longer HALT the whole active scan (the v3 bug)."""
        if self.stage >= 2:
            return self.stage
        alive, el, reason = self.ping()
        self.pings += 1
        if not alive:
            # Confirm-before-penalise: one re-probe after a short pause. Only a SECOND failure is a
            # real hard-fail (+2); a recovered re-probe is a transient blip worth just +1.
            time.sleep(self.confirm_delay)
            alive2, el2, reason2 = self.ping()
            self.pings += 1
            if not alive2:
                self.strikes += 2
                self.events.append(f"target {reason}/{reason2} x2 confirmed "
                                   f"({int(el)}ms/{int(el2)}ms, strikes={self.strikes})")
            else:
                self.strikes += 1
                self.events.append(f"target transient {reason} then alive "
                                   f"({int(el2)}ms, strikes={self.strikes})")
        elif el > self.slow_ms:
            self.strikes += 1
            self.events.append(f"target slow {int(el)}ms (strikes={self.strikes})")
        else:
            self.strikes = max(0, self.strikes - 1)  # recovery
        if self.strikes >= 4 and self.stage < 2:
            self.stage = 2
            self.events.append("HALT: target unhealthy, stopping active scan")
        elif self.strikes >= 2 and self.stage < 1:
            self.stage = 1
            self.events.append("BACKOFF: reducing injection depth (L5 -> L3)")
        return self.stage

    def recover_check(self, attempts: int = 3, delay: float = 20.0) -> int:
        """Called ONCE before the heaviest engine (ZAP). If the scan HALTed on a transient stress
        window, give the target a cooldown and re-probe: two healthy pings in a row demonstrate it
        recovered, so step the gate back from HALT(2) to BACKOFF(1) and let the cross-check engine
        run at reduced intensity rather than silently skipping it. A genuinely dead target keeps
        failing the probes and stays halted — protection intact. (v3: a mid-run dip during the
        hour-long nuclei-exposures stage permanently skipped ZAP; this gives it a second chance.)"""
        if self.stage < 2:
            return self.stage
        healthy = 0
        for _i in range(max(1, attempts)):
            time.sleep(delay)
            alive, el, reason = self.ping()
            self.pings += 1
            if alive:
                healthy += 1
                if healthy >= 2:
                    self.stage = 1
                    self.strikes = 2
                    self.events.append(f"RECOVERY: target responsive again after cooldown "
                                       f"({int(el)}ms) — re-enabling active scan at reduced depth")
                    return self.stage
            else:
                healthy = 0
                self.events.append(f"recovery probe {_i + 1}: still {reason} ({int(el)}ms)")
        self.events.append("recovery failed: target stayed unhealthy — active scan stays halted")
        return self.stage

    @property
    def halted(self) -> bool:
        return self.stage >= 2

    def sqlmap_level(self, base: int) -> int:
        """Adaptive sqlmap level: full at stage 0, capped at 3 once the target shows stress."""
        return base if self.stage == 0 else min(base, 3)


@dataclass
class LockoutMonitor:
    """Detect-and-back-off. Feed it each response; it decides whether to pause or halt."""
    max_strikes: int = 3
    backoff_s: float = 30.0
    strikes: int = 0
    tripped: bool = False
    events: list[str] = field(default_factory=list)

    def observe(self, status: int, final_url: str, body: str, had_session: bool) -> bool:
        """Return True if it is SAFE to continue, False if the scan should halt.
        A lockout/WAF signal adds a strike (and backs off); repeated signals halt the scan."""
        signal = None
        if status in (429, 503):
            signal = f"HTTP {status} (rate-limit/unavailable)"
        elif had_session and "login" in (urlsplit(final_url).path or "").lower():
            signal = "session bounced to login (possible lockout/expiry)"
        elif _LOCKOUT_TEXT.search(body or ""):
            m = _LOCKOUT_TEXT.search(body)
            signal = f"lockout/WAF text: {m.group(0)!r}"
        if not signal:
            return True
        self.strikes += 1
        self.events.append(signal)
        if self.strikes >= self.max_strikes:
            self.tripped = True
            return False
        time.sleep(self.backoff_s)   # back off, then allow a retry
        return True
