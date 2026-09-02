"""Authentication / session module.

Establish a login session ONCE (Playwright storageState, optionally with TOTP), persist it,
probe its validity before each scan, and translate the one captured session into the format
each downstream tool needs (cookie header, nuclei secrets file, sqlmap raw request, etc.).
"""

from __future__ import annotations

from .profile import AuthProfile, load_profile
from .session import Session

__all__ = ["AuthProfile", "Session", "load_profile"]
