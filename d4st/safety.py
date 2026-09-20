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

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# URL patterns we must NOT actively test (submitting payloads/failed logins here locks
# accounts or logs the scanner out).
_AUTH_PATH = re.compile(
    r"(login|logon|signin|sign-in|logout|signout|sign-out|auth|authenticate|"
    r"password|passwd|reset|forgot|register|signup|sign-up|sso|oauth|saml)",
    re.IGNORECASE,
)


def is_auth_endpoint(url: str) -> bool:
    return bool(_AUTH_PATH.search(urlsplit(url).path))


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
    policy allows). Checks path only, so a benign ?q=... query is not misclassified."""
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
    return POLICIES.get(name, POLICIES["engagement"])


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
    ping_timeout: float = 10.0
    stage: int = 0
    strikes: int = 0
    pings: int = 0
    events: list = field(default_factory=list)

    def ping(self) -> tuple[bool, float]:
        """Active liveness GET on the base URL. Returns (alive, elapsed_ms). alive is False on
        connection error/timeout or any 5xx (the signals a stressed app emits before dying)."""
        import httpx
        # verify=False: an invalid/self-signed cert (routine in pentests — islclinic.net IS the cert
        # finding) must NOT read as "target down". Without it every ping throws SSLError -> the target
        # is falsely halted, silently skipping the DOM stage, ZAP, and deep injection. browser UA so a
        # WAF doesn't tarpit the liveness ping either.
        headers = browser_headers({"Cookie": self.cookie} if self.cookie else None)
        t0 = time.monotonic()
        try:
            r = httpx.get(self.base_url, headers=headers, timeout=self.ping_timeout,
                          follow_redirects=True, verify=False)
            return (r.status_code < 500, (time.monotonic() - t0) * 1000.0)
        except Exception:  # noqa: BLE001 - any failure = not alive
            return (False, (time.monotonic() - t0) * 1000.0)

    def check(self) -> int:
        """Ping and update the stress stage. Returns the current stage (0/1/2). Once halted it
        stays halted (no thrashing back to active scanning)."""
        if self.stage >= 2:
            return self.stage
        alive, el = self.ping()
        self.pings += 1
        if not alive:
            self.strikes += 2
            self.events.append(f"target unresponsive/5xx (strikes={self.strikes})")
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
