"""Configuration loading. All settings come from the environment (D4ST_ prefix).

Kept deliberately dependency-free so the orchestrator can load config without a DB or
any tool present (needed for --dry-run and unit tests).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


@dataclass
class Config:
    database_url: str | None = None
    api_keys: list[str] = field(default_factory=list)
    verify_egress_ips: list[str] = field(default_factory=list)
    interactsh_server: str | None = None
    asmng_api_url: str | None = None
    asmng_api_key: str | None = None
    # Where run artifacts and captured sessions live.
    runs_dir: str = "runs"
    sessions_dir: str = "sessions"
    # Operator path-exclusion carve-out (D4ST_EXCLUDE_PATHS): comma-separated regex/glob/substring
    # path patterns whose matching endpoints must NEVER receive an intrusive / state-changing /
    # form-submitting request (they are still passively GET-crawled so they appear in the sitemap).
    # See d4st/safety.py ExcludePathMatcher for the exact pattern format. Raw list kept here; the
    # compiled matcher is exposed via .exclude_matcher.
    exclude_paths: list[str] = field(default_factory=list)
    # Session-validity self-test MODE (D4ST_SESSION_VALIDITY_MODE). Fail-closed gate run before an
    # authenticated engagement starts. See d4st/auth/validity.py validate_session().
    #   "rendered"   (DEFAULT) : unchanged legacy rendered portal-marker probe (web/cookie apps).
    #   "basic-auth"           : validate the configured HTTP Basic-Auth 401->200 transition
    #                            (for API-auth engagements where the real auth is the Authorization
    #                            header, not a portal cookie — the rendered probe wrongly blocks).
    #   "both"                 : rendered AND basic-auth must both pass.
    # The basic-auth mode needs an endpoint + credentials (next three fields); a basic-auth/both
    # mode with any of them missing ABORTS at construction (fail-closed, never skips validation).
    session_validity_mode: str = "rendered"
    session_validity_probe_url: str | None = None   # D4ST_SESSION_VALIDITY_URL (basic-auth probe)
    basic_auth_user: str | None = None              # D4ST_BASIC_AUTH_USER (email / username)
    basic_auth_pass: str | None = None              # D4ST_BASIC_AUTH_PASS

    def __post_init__(self):
        # SINGLE SOURCE OF TRUTH / no latent fail-open: building ANY Config that carries exclude
        # patterns INSTALLS them as the engine's active matcher, so a programmatic
        # ``Config(exclude_paths=[...])`` enforces exactly like the env var does (the engine's
        # policy-less gates all consult the active matcher). Fails closed on a bad pattern.
        if self.exclude_paths:
            from .safety import set_exclude_matcher
            set_exclude_matcher(",".join(self.exclude_paths))
        # Validate the session-validity mode here so a malformed/incomplete config ABORTS before
        # any engagement starts (fail-closed, mirrors exclude_paths). normalize_validity_mode()
        # RAISES on an unknown mode; a basic-auth/both mode with no probe endpoint+creds RAISES too
        # — the gate must never be reachable in a weaker-than-configured state.
        from .auth.validity import SessionValidityConfigError, normalize_validity_mode
        self.session_validity_mode = normalize_validity_mode(self.session_validity_mode)
        if self.session_validity_mode in ("basic-auth", "both"):
            missing = [name for name, val in (
                ("D4ST_SESSION_VALIDITY_URL", self.session_validity_probe_url),
                ("D4ST_BASIC_AUTH_USER", self.basic_auth_user),
                ("D4ST_BASIC_AUTH_PASS", self.basic_auth_pass),
            ) if not val]
            if missing:
                raise SessionValidityConfigError(
                    f"session-validity mode {self.session_validity_mode!r} requires "
                    f"{', '.join(missing)} (missing/empty) — refusing to start with a "
                    f"session-validity gate that cannot run")

    @property
    def exclude_matcher(self):
        """The compiled D4ST_EXCLUDE_PATHS matcher for this config — the SAME object the engine
        enforces with (installed as the active matcher by __post_init__), not a dead parallel copy.
        When this config carries no patterns, returns the currently-active matcher."""
        from .safety import ExcludePathMatcher, get_exclude_matcher, set_exclude_matcher
        if self.exclude_paths:
            return set_exclude_matcher(ExcludePathMatcher(",".join(self.exclude_paths)))
        return get_exclude_matcher()

    @classmethod
    def from_env(cls) -> Config:
        db_url = os.environ.get("D4ST_DATABASE_URL")
        if not db_url:
            pw = os.environ.get("D4ST_DB_PASSWORD")
            if pw:
                db_url = f"postgresql://d4st:{pw}@localhost:5433/d4st"
        return cls(
            database_url=db_url,
            api_keys=_split_csv(os.environ.get("D4ST_API_KEYS")),
            verify_egress_ips=_split_csv(os.environ.get("D4ST_VERIFY_EGRESS_IPS")),
            interactsh_server=os.environ.get("D4ST_INTERACTSH_SERVER") or None,
            asmng_api_url=os.environ.get("D4ST_ASMNG_API_URL") or None,
            asmng_api_key=os.environ.get("D4ST_ASMNG_API_KEY") or None,
            runs_dir=os.environ.get("D4ST_RUNS_DIR", "runs"),
            sessions_dir=os.environ.get("D4ST_SESSIONS_DIR", "sessions"),
            exclude_paths=_split_csv(os.environ.get("D4ST_EXCLUDE_PATHS")),
            session_validity_mode=os.environ.get("D4ST_SESSION_VALIDITY_MODE", "rendered"),
            session_validity_probe_url=os.environ.get("D4ST_SESSION_VALIDITY_URL") or None,
            basic_auth_user=os.environ.get("D4ST_BASIC_AUTH_USER") or None,
            basic_auth_pass=os.environ.get("D4ST_BASIC_AUTH_PASS") or None,
        )
