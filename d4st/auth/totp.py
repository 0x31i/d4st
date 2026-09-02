"""TOTP helper. Generates the current 6-digit code from a shared secret (the same seed the
authenticator app holds), enabling fully unattended MFA for TOTP-based logins.

Push/SMS OTP cannot be automated this way (see the plan); those need a scan/service account,
an IP-allowlist bypass, or a one-time human-assisted capture.
"""

from __future__ import annotations

import os


def totp_now(secret: str) -> str:
    import pyotp
    return pyotp.TOTP(secret).now()


def totp_from_env(env_var: str) -> str | None:
    secret = os.environ.get(env_var)
    if not secret:
        return None
    return totp_now(secret)
