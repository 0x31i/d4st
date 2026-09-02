"""Bridge between the orchestrator's session dict (RunContext.session) and the auth
translators. RunContext carries the session as a plain dict (Session.to_dict()) so the
orchestrator stays decoupled from the auth model; adapters use this helper to turn it into
tool-specific args.
"""

from __future__ import annotations

from ...auth.session import Session
from ...auth.translators import header_args


def _session(session_dict) -> Session | None:
    if not session_dict:
        return None
    if isinstance(session_dict, Session):
        return session_dict
    try:
        return Session.from_dict(session_dict)
    except Exception:  # noqa: BLE001 - never let a bad session dict crash an adapter
        return None


def _session_header_args(session_dict, url: str | None = None) -> list[str]:
    sess = _session(session_dict)
    if sess is None:
        return []
    return header_args(sess, url)


def _cookie_header(session_dict, url: str | None = None) -> str:
    sess = _session(session_dict)
    return sess.cookie_header(url) if sess else ""
