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
