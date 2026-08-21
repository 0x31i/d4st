"""Translate ONE captured Session into the format each downstream tool consumes.

This is the fan-out layer: capture the login once, then every scanner (katana, nuclei, ZAP,
sqlmap, dalfox) inherits the same session through its own native mechanism. Pure functions,
no tool required, fully unit-testable.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from .session import Session


def header_args(session: Session, url: str | None = None) -> list[str]:
    """`-H "Cookie: ..."` (+ any extra headers) as repeated CLI args. Used by katana, nuclei,
    dalfox, sqlmap and most Go/Python tools that accept -H."""
    args: list[str] = []
    cookie = session.cookie_header(url)
    if cookie:
        args += ["-H", f"Cookie: {cookie}"]
    for k, v in session.headers.items():
        args += ["-H", f"{k}: {v}"]
    return args


def dalfox_cookie(session: Session, url: str | None = None) -> str:
    """Value for dalfox --cookie."""
    return session.cookie_header(url)


def nuclei_secrets(session: Session, domains: list[str]) -> dict:
    """A nuclei -secret-file document (domain-scoped static auth). Cookies as a cookiesAuth
    strategy; extra headers as headersAuth. Returned as a dict; caller dumps YAML."""
    static: list[dict] = []
    cookies = session.cookies
    if cookies:
        static.append({
            "type": "cookiesAuth",
            "domains": domains,
            "cookies": [{"key": c["name"], "value": c["value"]}
                        for c in cookies if c.get("name")],
        })
    if session.headers:
        static.append({
            "type": "headersAuth",
            "domains": domains,
            "headers": [{"key": k, "value": v} for k, v in session.headers.items()],
        })
    return {"static": static}


def sqlmap_request_file(session: Session, url: str, method: str = "GET",
                        body: str = "") -> str:
    """A raw HTTP request for `sqlmap -r <file>`, carrying the session cookies + headers so
    all injection points are tested authenticated."""
    parts = urlsplit(url)
    host = parts.netloc
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {host}"]
    cookie = session.cookie_header(url)
    if cookie:
        lines.append(f"Cookie: {cookie}")
    for k, v in session.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("Connection: close")
    lines.append("")
    if body:
        lines.append(body)
    return "\r\n".join(lines)
