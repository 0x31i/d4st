"""Headless-Chrome screenshot capture — courtroom-grade visual evidence of an app/API state.

A pentest proof is often visual: the rendered page showing an exploit's effect, an API JSON
response rendered in the browser, a stored-XSS `alert()` firing, a privilege escalation visible
in the UI. `capture()` drives a headless Chromium (via Playwright) to that state and freezes it to
a PNG, recording a sha256 of the image bytes and a UTC timestamp so the shot can anchor an
evidence chain-of-custody.

Public-tool posture (hard rule): this is a generic capture primitive. It knows nothing about any
particular engagement or driver. The only extension seam is a neutral, pluggable `policy(method,
url)` hook — an outside caller injects its own pre-send / scope / egress check without this module
knowing what it is. The policy is consulted BEFORE the browser is launched or the network touched,
so a blocked URL never renders.

Read-only posture: the top-level navigation is a GET. `eval_js`, however, is operator-supplied and
CAN cause side effects — it runs real JavaScript in the page and may trigger state-changing
requests (clicking, submitting, fetch()). This module deliberately does NOT police `eval_js`: a
caller that wants strictly read-only evidence must pass benign JS only (e.g. reveal/scroll/read
DOM), and the pluggable `policy` hook is where an embedding driver enforces that decision.

Playwright is imported lazily inside `capture()` so `import d4st.shot` never fails on a host
without the browser engine; a clear RuntimeError with an install hint is raised if it is missing
(mirrors how `d4st.proxy` defers its optional mitmproxy import). The screenshot engine is declared
as the `[shot]` optional extra: pip install 'd4st[shot]'.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional, Union

# A policy returns either a bare bool, or an (ok, reason) tuple. d4st attaches no meaning to it
# beyond allow / deny — the embedding driver pins scope / egress / ROE through it.
PolicyResult = Union[bool, "tuple[bool, str]"]
Policy = Callable[[str, str], PolicyResult]


@dataclass
class ShotResult:
    path: str                 # absolute path to the captured PNG
    url: str                  # final URL after any redirects
    requested_url: str        # the URL asked for
    title: str                # document.title
    width: int
    height: int
    full_page: bool
    element_selector: Optional[str]
    sha256: str               # sha256 of the PNG bytes (integrity for evidence chain)
    captured_at: str          # ISO8601 UTC
    console: list = field(default_factory=list)   # console messages during render (truncated)
    status: Optional[int] = None  # top-level navigation HTTP status if available
    error: Optional[str] = None   # non-fatal note (e.g. wait_selector timed out but we still shot)


# --------------------------------------------------------------------------------------------------
# Pure helpers (no browser, no network) — unit-testable on their own.
# --------------------------------------------------------------------------------------------------
def _normalize_policy(result: PolicyResult) -> "tuple[bool, str]":
    """Accept both policy return styles and normalize to (ok, reason).

    A bare bool carries no reason; a 2-tuple carries an explicit one. Anything else is treated as
    truthiness with a generic reason so a malformed policy fails safe-ish but predictably."""
    if isinstance(result, tuple):
        ok = bool(result[0])
        reason = str(result[1]) if len(result) > 1 and result[1] else ("allowed" if ok else "blocked by policy")
        return ok, reason
    ok = bool(result)
    return ok, ("allowed" if ok else "blocked by policy")


def _build_result(png_bytes: bytes, *, path: str, requested_url: str, final_url: str, title: str,
                  width: int, height: int, full_page: bool, element_selector: Optional[str],
                  console: Optional[list] = None, status: Optional[int] = None,
                  error: Optional[str] = None) -> ShotResult:
    """Assemble a ShotResult from captured PNG bytes + page metadata.

    Factored out of `capture()` so the evidence-chain fields (sha256 of the exact bytes, UTC
    capture timestamp) can be unit-tested without launching a browser."""
    sha = hashlib.sha256(png_bytes).hexdigest()
    captured_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return ShotResult(
        path=os.path.abspath(path),
        url=final_url,
        requested_url=requested_url,
        title=title,
        width=width,
        height=height,
        full_page=full_page,
        element_selector=element_selector,
        sha256=sha,
        captured_at=captured_at,
        console=list(console or []),
        status=status,
        error=error,
    )


def _default_out_path() -> str:
    """Timestamped PNG path under <tempdir>/d4st-shots/ (parent dir ensured)."""
    out_dir = os.path.join(tempfile.gettempdir(), "d4st-shots")
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return os.path.join(out_dir, f"shot-{stamp}-{os.getpid()}.png")


def _require_playwright():
    """Lazy import of Playwright's sync API with a clear install hint (mirrors proxy.py's deferral)."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # noqa: BLE001
        raise RuntimeError(
            "the screenshot feature needs Playwright + Chromium: pip install 'd4st[shot]' "
            "&& python -m playwright install chromium"
        ) from exc
    return sync_playwright


# Cap console capture so a chatty page can't bloat the evidence record.
_CONSOLE_MAX = 50
_CONSOLE_MSG_MAX = 500


def capture(
    url: str,
    *,
    out_path: Optional[str] = None,
    cookies: Optional[list] = None,
    headers: Optional[dict] = None,
    eval_js: Optional[str] = None,
    wait_selector: Optional[str] = None,
    wait_ms: int = 0,
    full_page: bool = True,
    element_selector: Optional[str] = None,
    viewport: "tuple[int, int]" = (1440, 900),
    timeout: float = 30.0,
    policy: Optional[Policy] = None,
    ignore_https_errors: bool = True,
) -> ShotResult:
    """Capture a PNG of `url` rendered in headless Chromium and return a ShotResult.

    The navigation is a GET. Cookies/headers let an AUTHENTICATED state be rendered. `eval_js` runs
    AFTER load and BEFORE the shot — use it to reveal or trigger the state you want to prove.

    WARNING: `eval_js` is operator-supplied JavaScript and MAY cause side effects / state-changing
    requests (it can click, submit, or fetch()). This primitive does not police it. For strictly
    read-only visual evidence, pass only benign JS (reveal/scroll/read-DOM); the `policy` hook is
    where an embedding driver enforces scope / egress / ROE.

    Policy ordering (a security property): if `policy` is provided it is called as policy("GET",
    url) FIRST, before Playwright is imported or the browser launched. A denial raises
    PermissionError and nothing on the network is touched.

    `wait_selector` is best-effort: if it times out the page is still captured and `error` is set,
    so a flaky/500-prone bench target almost never hard-fails a capture.

    Args:
        out_path: where to write the PNG; if None, auto-named under <tempdir>/d4st-shots/.
        cookies: Playwright cookie dicts (name,value,domain,path,secure,httpOnly,sameSite).
        headers: extra HTTP headers for the navigation.
        eval_js: JS evaluated after load, before capture (may have side effects — see WARNING).
        wait_selector: CSS selector to wait for before capture (best-effort).
        wait_ms: extra fixed wait (ms) after load.
        full_page: capture the full scrollable page (default True).
        element_selector: if set, screenshot only this element (overrides full_page).
        viewport: (width, height) of the browser viewport.
        timeout: per-operation timeout in seconds.
        policy: callable policy(method, url) -> bool | (ok, reason); checked before launch.
        ignore_https_errors: tolerate self-signed/invalid certs (bench default True).

    Returns:
        ShotResult with the PNG path, sha256 of the bytes, and UTC capture timestamp.

    Raises:
        PermissionError: the policy denied the URL (raised before any browser/network activity).
        RuntimeError: Playwright/Chromium is not installed.
    """
    # 1. Policy gate FIRST — before the lazy import, before any network. This ordering is the
    #    security property the private driver pins egress/scope through; keep it first.
    if policy is not None:
        ok, reason = _normalize_policy(policy("GET", url))
        if not ok:
            raise PermissionError(reason)

    out_path = out_path or _default_out_path()
    parent = os.path.dirname(os.path.abspath(out_path))
    if parent:
        os.makedirs(parent, exist_ok=True)

    sync_playwright = _require_playwright()

    timeout_ms = max(0.0, float(timeout)) * 1000.0
    vw, vh = int(viewport[0]), int(viewport[1])
    console_msgs: list = []
    error_note: Optional[str] = None
    status: Optional[int] = None

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(
                viewport={"width": vw, "height": vh},
                ignore_https_errors=ignore_https_errors,
                extra_http_headers=(headers or None),
            )
            if cookies:
                # Cookie dicts are already Playwright-shaped; inject before navigation so the
                # authenticated render is served.
                context.add_cookies(cookies)

            page = context.new_page()
            page.set_default_timeout(timeout_ms)

            def _on_console(msg) -> None:
                if len(console_msgs) >= _CONSOLE_MAX:
                    return
                try:
                    text = f"{msg.type}: {msg.text}"
                except Exception:  # noqa: BLE001 — never let a console listener break a capture
                    text = "<unreadable console message>"
                console_msgs.append(text[:_CONSOLE_MSG_MAX])

            page.on("console", _on_console)

            response = page.goto(url, wait_until="load", timeout=timeout_ms)
            if response is not None:
                try:
                    status = response.status
                except Exception:  # noqa: BLE001
                    status = None
            final_url = page.url

            # eval_js: operator-supplied; may reveal/trigger the state being proved (see WARNING).
            if eval_js:
                try:
                    page.evaluate(eval_js)
                except Exception as exc:  # noqa: BLE001 — a bad eval must not lose the shot
                    error_note = _append_note(error_note, f"eval_js error: {exc}")

            # wait_selector: best-effort — on timeout still capture and record the note.
            if wait_selector:
                try:
                    page.wait_for_selector(wait_selector, timeout=timeout_ms)
                except Exception:  # noqa: BLE001
                    error_note = _append_note(
                        error_note, f"wait_selector {wait_selector!r} timed out; captured anyway")

            if wait_ms and wait_ms > 0:
                page.wait_for_timeout(wait_ms)

            try:
                title = page.title()
            except Exception:  # noqa: BLE001
                title = ""

            # Capture: a single element (overrides full_page) or the page.
            if element_selector:
                handle = page.query_selector(element_selector)
                if handle is not None:
                    png_bytes = handle.screenshot()
                else:
                    error_note = _append_note(
                        error_note,
                        f"element_selector {element_selector!r} not found; captured full page")
                    png_bytes = page.screenshot(full_page=full_page)
            else:
                png_bytes = page.screenshot(full_page=full_page)

            with open(out_path, "wb") as fh:
                fh.write(png_bytes)
        finally:
            browser.close()

    return _build_result(
        png_bytes, path=out_path, requested_url=url, final_url=final_url, title=title,
        width=vw, height=vh, full_page=False if element_selector else full_page,
        element_selector=element_selector, console=console_msgs, status=status, error=error_note,
    )


def _append_note(existing: Optional[str], note: str) -> str:
    """Join multiple non-fatal notes into the single `error` field."""
    return note if not existing else f"{existing}; {note}"
