"""Canonical engagement-scope host filtering.

ONE definition of "is this URL in scope", reused by BOTH scan paths:
  - the unauthenticated `engagement`/`unauth` path (d4st.engagement), and
  - the `launch`/WorkflowRunner path (d4st.orchestrator.workflow).

Why this exists: discovery drags in third-party resource URLs (fonts.googleapis.com,
docs.google.com, view.officeapps.live.com, CDNs, analytics). Those must NEVER reach the
active/injection tools — sending attack payloads off-scope is both a false-finding source
AND a rules-of-engagement violation. Scope is enforced at the frontier so every downstream
consumer (dalfox, sstimap, sqlmap, nuclei-dast, …) only ever sees in-scope targets.

Scope = D4ST_SCOPE_HOSTS (comma list) if set, else the target's own host. A bare domain in
the list also matches its subdomains (e.g. `example.com` covers `app.example.com`).
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit


def _host(url: str) -> str:
    """Lowercased hostname (no port / userinfo). '' for host-less / relative URLs."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except (ValueError, AttributeError):
        return ""


def scope_hosts(target: str, env: str | None = None) -> list[str]:
    """In-scope hosts for a run.

    `env` overrides the D4ST_SCOPE_HOSTS lookup (for testing / explicit callers). When neither
    is set, scope defaults to the target's own host.
    """
    raw = (env if env is not None else os.environ.get("D4ST_SCOPE_HOSTS", "")).strip()
    hosts = [h.strip().lower() for h in raw.split(",") if h.strip()]
    if hosts:
        return hosts
    h = _host(target)
    return [h] if h else []


def in_scope(url: str, hosts) -> bool:
    """True if `url`'s host equals an in-scope host or is a subdomain of one.

    Host-less / relative URLs are treated as in-scope (they resolve against the target and
    cannot carry an off-scope host). An empty `hosts` list means "no restriction" (in-scope),
    so a mis-derived scope never silently drops the entire frontier.
    """
    if not hosts:
        return True
    h = _host(url)
    if not h:
        return True
    return any(h == s or h.endswith("." + s) for s in hosts)


def in_scope_pred(hosts):
    """Return a single-arg predicate `f(url) -> bool` bound to `hosts` (for the Frontier)."""
    return lambda u: in_scope(u, hosts)
