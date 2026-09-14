"""Single-file engagement configuration — the auto-glue that replaces hand-set env vars.

One `engagement.yaml` per client declares the whole run: target, scope, auth (with creds), scan
profile, tuning knobs, an optional second account for the BOLA matrix, egress allow-list, and report
metadata. `d4st run engagement.yaml` then:
  1. captures a fresh session from the declared auth profile+creds (no separate `auth capture` step),
  2. derives + exports every D4ST_* knob the engine reads (scope, full-capture, JS depth, secret
     validation, method-tamper writes, JWT wordlist, verify egress, 2nd-account session), and
  3. runs the engagement.

So an operator configures a target ONCE in readable YAML instead of remembering ~8 environment
variables and a capture incantation. Env vars still work as per-run overrides (they win over config).
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit


class ConfigError(Exception):
    pass


_DEFAULT_TUNING = {
    "full_capture": True,       # -> D4ST_FULL_CAPTURE
    "js_max": 8000,             # -> D4ST_JS_MAX
    "secret_validate": False,   # -> D4ST_SECRET_VALIDATE (live vendor check; egresses to 3rd party)
    "method_tamper_writes": False,   # -> D4ST_METHOD_TAMPER_WRITES (never mutates unless true)
    "jwt_wordlist": None,       # -> D4ST_JWT_WORDLIST (extra HS-secret guesses)
}


def load(path: str) -> dict:
    """Load + validate an engagement YAML, filling defaults. Returns a resolved config dict."""
    import yaml
    if not os.path.exists(path):
        raise ConfigError(f"engagement config not found: {path}")
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    if not isinstance(raw, dict):
        raise ConfigError("engagement config must be a YAML mapping")
    return resolve(raw, cfg_path=path)


def resolve(raw: dict, *, cfg_path: str = "") -> dict:
    target = (raw.get("target") or "").strip()
    if not target:
        raise ConfigError("engagement config requires a 'target' URL")
    host = urlsplit(target).hostname or ""
    if not host:
        raise ConfigError(f"target is not a valid URL: {target!r}")

    slug = _slug(raw.get("client") or host)
    cfg = {
        "client": raw.get("client") or host,
        "target": target,
        "host": host,
        "scope": [s.strip().lower() for s in (raw.get("scope") or [host]) if s and s.strip()],
        "profile": raw.get("profile") or "engagement",
        "depth": int(raw.get("depth") or 3),
        "output": raw.get("output") or f"results/{slug}.json",
        "tuning": {**_DEFAULT_TUNING, **(raw.get("tuning") or {})},
        "egress": raw.get("egress") or {},
        "report": raw.get("report") or {},
        "auth": _resolve_auth(raw.get("auth") or {}, slug),
        "_cfg_path": cfg_path,
    }
    return cfg


def _resolve_auth(a: dict, slug: str) -> dict:
    if not a:
        raise ConfigError("engagement config requires an 'auth' block (profile + creds or a session)")
    out = {
        "profile": a.get("profile"),
        "username": a.get("username") or (os.environ.get(a["username_env"]) if a.get("username_env") else None),
        "password": a.get("password") or (os.environ.get(a["password_env"]) if a.get("password_env") else None),
        "session": a.get("session") or f"sessions/{slug}.json",
        "reuse_if_fresh": bool(a.get("reuse_if_fresh", True)),
        "interactive": bool(a.get("interactive", False)),
        "second": None,
    }
    sec = a.get("second")
    if sec:
        out["second"] = {
            "profile": sec.get("profile") or a.get("profile"),
            "username": sec.get("username") or (os.environ.get(sec["username_env"]) if sec.get("username_env") else None),
            "password": sec.get("password") or (os.environ.get(sec["password_env"]) if sec.get("password_env") else None),
            "session": sec.get("session") or f"sessions/{slug}-b.json",
        }
    return out


def apply_env(cfg: dict) -> dict:
    """Export the D4ST_* knobs derived from the config. Existing env vars WIN (per-run override).
    Returns a dict of what was set, for logging."""
    t = cfg["tuning"]
    set_map = {
        "D4ST_SCOPE_HOSTS": ",".join(cfg["scope"]),
        "D4ST_FULL_CAPTURE": "1" if t["full_capture"] else "0",
        "D4ST_JS_MAX": str(t["js_max"]),
        "D4ST_SECRET_VALIDATE": "1" if t["secret_validate"] else "",
        "D4ST_METHOD_TAMPER_WRITES": "1" if t["method_tamper_writes"] else "",
        "D4ST_JWT_WORDLIST": t.get("jwt_wordlist") or "",
    }
    # egress allow-list for the verify seatbelt: explicit IPs, or "auto" to detect the box's egress
    verify = cfg["egress"].get("verify_ips")
    if verify == "auto" or verify == ["auto"]:
        ip = _detect_egress_ip()
        if ip:
            set_map["D4ST_VERIFY_EGRESS_IPS"] = ip
    elif verify:
        set_map["D4ST_VERIFY_EGRESS_IPS"] = ",".join(verify) if isinstance(verify, list) else str(verify)

    applied = {}
    for k, v in set_map.items():
        if not v:
            continue
        if os.environ.get(k):          # a real per-run override already set — respect it
            applied[k] = os.environ[k] + " (env override)"
            continue
        os.environ[k] = v
        applied[k] = v
    return applied


def _detect_egress_ip() -> str:
    try:
        import httpx
        return (httpx.get("https://api.ipify.org", timeout=8).text or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def _slug(s: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9._-]+", "-", (s or "scan")).strip("-").lower() or "scan"


EXAMPLE = """\
# d4st engagement — one file per client. Run with:  d4st run engagement.yaml
client: "Example Health"                 # report label + default file slugs
target: https://app.example.com          # required
scope:                                    # hosts in scope (default: the target host only)
  - app.example.com
profile: engagement                       # scan policy (engagement | safe-deep | production-safe | ...)
depth: 3
output: results/example.json              # default: results/<client-slug>.json

auth:
  profile: d4st/auth/profiles/example.yaml   # login recipe (see `d4st auth init` to generate one)
  username_env: EXAMPLE_USER               # or: username: alice   (env is safer than plaintext)
  password_env: EXAMPLE_PASS               # or: password: ...
  session: sessions/example.json           # where the captured session is stored
  reuse_if_fresh: true                     # skip re-capture if the stored session is still valid
  # second account unlocks the two-account horizontal BOLA/IDOR matrix:
  # second:
  #   username_env: EXAMPLE_USER_B
  #   password_env: EXAMPLE_PASS_B

tuning:
  full_capture: true          # Burp-grade full request/response proof on every finding
  js_max: 8000                # max JS bundles to deep-scan (chunk auto-expansion)
  secret_validate: false      # live-check disclosed keys (egresses to the vendor; opt-in)
  method_tamper_writes: false # probe POST/PUT/DELETE for BFLA (MUTATES; opt-in only)
  jwt_wordlist: null          # path to extra HS256 signing-secret guesses

egress:
  verify_ips: auto            # allow-list for the read-only verify seatbelt ("auto" = detect this host's egress)

report:
  client: "Example Health, Inc."
  ref: "External web app assessment"
"""
