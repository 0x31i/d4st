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
        )
