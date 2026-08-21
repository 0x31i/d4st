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
        if self.delay_ms:
            f += ["-delay", f"{self.delay_ms}ms"]
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


# Named profiles.
POLITE = Politeness(rps=2.0, concurrency=2, delay_ms=250)     # production / lockout-prone
NORMAL = Politeness(rps=8.0, concurrency=8, delay_ms=0)        # test env
AGGRESSIVE = Politeness(rps=25.0, concurrency=20, delay_ms=0)  # owned lab, allowlisted

PROFILES = {"polite": POLITE, "normal": NORMAL, "aggressive": AGGRESSIVE}


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


# Named policies. 'production-safe' is the locked-down default for live/client infra.
POLICIES: dict[str, ScanPolicy] = {
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
    return POLICIES.get(name, POLICIES["staging"])


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
