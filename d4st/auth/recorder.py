"""Record-to-configure auth: watch a human log in ONCE in a real browser, then auto-generate the
auth profile. This removes the hardest part of onboarding a new target — writing login-form CSS
selectors and hunting for the bearer-token key by hand.

How it works (`d4st auth init <login-url>`):
  1. Launch a headed Chromium and inject a tiny recorder that reports every field the user types in
     and the control they click, with a best-effort CSS selector for each (id > name > type path).
  2. Snapshot sessionStorage/localStorage BEFORE login; wait for the user to finish (URL leaves the
     login page OR a JWT-looking value appears in storage); snapshot AFTER.
  3. Infer the username/password/submit selectors from the recorded interactions, and detect the
     bearer token by diffing storage (a new eyJ… value = the JWT).
  4. Write a ready AuthProfile YAML (portable: login_url stored as {base}/path) and, optionally,
     capture the session immediately.

The pure inference (infer_selectors / detect_token) is unit-tested; the browser orchestration needs
a display, so `auth init` is a setup-time tool the operator runs locally, not on the headless box.
"""

from __future__ import annotations

import re

# JWT-ish value: three base64url segments (header.payload.sig), header starts eyJ
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.?[A-Za-z0-9_\-]*$")

# Injected once per document: build a stable CSS selector for an element and report every text-input
# and click back to Python via the exposed __d4stRecord binding (survives navigation — re-injected).
_INIT_JS = r"""
() => {
  const cssPath = (el) => {
    if (!el || el.nodeType !== 1) return "";
    if (el.id) return "#" + CSS.escape(el.id);
    if (el.name) return el.tagName.toLowerCase() + "[name=\"" + el.name + "\"]";
    const parts = [];
    let e = el;
    while (e && e.nodeType === 1 && parts.length < 5) {
      let sel = e.tagName.toLowerCase();
      if (e.type) sel += "[type=\"" + e.type + "\"]";
      const par = e.parentElement;
      if (par) {
        const sibs = Array.from(par.children).filter(c => c.tagName === e.tagName);
        if (sibs.length > 1) sel += ":nth-of-type(" + (sibs.indexOf(e) + 1) + ")";
      }
      parts.unshift(sel);
      e = e.parentElement;
    }
    return parts.join(" > ");
  };
  const rec = (o) => { try { window.__d4stRecord(o); } catch (e) {} };
  document.addEventListener("input", (ev) => {
    const t = ev.target;
    if (t && t.tagName === "INPUT") rec({kind: "input", sel: cssPath(t),
      type: (t.type || "text").toLowerCase(), name: t.name || "", id: t.id || ""});
  }, true);
  const onClick = (ev) => {
    const t = (ev.target.closest && ev.target.closest("button,input[type=submit],input[type=button],[role=button],a")) || ev.target;
    if (t) rec({kind: "click", sel: cssPath(t), text: (t.innerText || t.value || "").slice(0, 40)});
  };
  document.addEventListener("click", onClick, true);
}
"""


def infer_selectors(events: list[dict]) -> tuple[str, str, str]:
    """From recorded input/click events, infer (username_selector, password_selector, submit_selector).
    - password: the last INPUT of type password.
    - username: the last non-password text/email INPUT before that password (else the last text input).
    - submit:   the last click on a button/submit control."""
    inputs = [e for e in events if e.get("kind") == "input"]
    clicks = [e for e in events if e.get("kind") == "click"]
    pw = next((e for e in reversed(inputs) if e.get("type") == "password"), None)
    pw_sel = pw["sel"] if pw else "input[type=\"password\"]"
    pw_idx = inputs.index(pw) if pw else len(inputs)
    user = next((e for e in reversed(inputs[:pw_idx])
                 if e.get("type") in ("text", "email", "tel", "")), None)
    if not user:
        user = next((e for e in reversed(inputs) if e.get("type") != "password"), None)
    user_sel = user["sel"] if user else "input[name=\"username\"]"
    submit_sel = clicks[-1]["sel"] if clicks else "button[type=\"submit\"], input[type=\"submit\"]"
    return user_sel, pw_sel, submit_sel


def detect_token(pre: dict, post: dict) -> dict:
    """Diff two {storage_name: {k: v}} snapshots and return the bearer token descriptor
    {key, storage, header, scheme} — preferring a JWT-looking value that is new/changed after login."""
    candidates = []          # (score, key, storage)
    for storage in ("session", "local"):
        before, after = pre.get(storage, {}) or {}, post.get(storage, {}) or {}
        for k, v in after.items():
            if not isinstance(v, str) or len(v) < 16:
                continue
            changed = before.get(k) != v
            is_jwt = bool(_JWT_RE.match(v.strip()))
            keyish = any(w in k.lower() for w in ("token", "jwt", "auth", "access", "bearer", "id_token"))
            score = (2 if is_jwt else 0) + (1 if changed else 0) + (1 if keyish else 0)
            if score:
                candidates.append((score, len(v), k, storage))
    if not candidates:
        return {}
    candidates.sort(reverse=True)
    _, _, key, storage = candidates[0]
    return {"key": key, "storage": storage, "header": "Authorization", "scheme": "Bearer "}


def build_profile(name: str, login_url: str, base: str, user_sel: str, pw_sel: str,
                  submit_sel: str, token: dict, success_url_path: str, landed_url: str) -> dict:
    """Assemble a portable AuthProfile dict. login_url is stored as {base}/path so one profile
    works across environments (base supplied at run time)."""
    from urllib.parse import urlsplit
    lp = urlsplit(login_url).path or "/login"
    prof = {
        "name": name,
        "type": "token" if token else "form",
        "login_url": "{base}" + lp,
        "username_selector": user_sel,
        "password_selector": pw_sel,
        "submit_selector": submit_sel,
        "username_env": f"{name.upper()}_USERNAME",
        "password_env": f"{name.upper()}_PASSWORD",
        "success": {},
        "validity": {},
    }
    if success_url_path:
        prof["success"]["url_contains"] = success_url_path
        prof["validity"]["url"] = "{base}" + success_url_path
    if token:
        prof["token"] = token
    return prof


def record_login(login_url: str, name: str, base: str | None = None, *,
                 timeout_ms: int = 300000) -> tuple[dict, object]:
    """Drive a headed browser; the human logs in; return (profile_dict, Session). Needs a display."""
    from playwright.sync_api import sync_playwright

    from urllib.parse import urlsplit
    from .capture import _apply_bearer, _dump_session_storage
    from .session import Session

    origin = f"{urlsplit(login_url).scheme}://{urlsplit(login_url).netloc}"
    base = (base or origin).rstrip("/")
    login_path = urlsplit(login_url).path or "/login"
    events: list[dict] = []

    def _local_storage(page) -> dict:
        try:
            return page.evaluate("() => { const o={}; for (let i=0;i<localStorage.length;i++)"
                                 "{const k=localStorage.key(i); o[k]=localStorage.getItem(k);} return o; }") or {}
        except Exception:  # noqa: BLE001
            return {}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        ctx = browser.new_context()
        ctx.expose_binding("__d4stRecord", lambda source, o: events.append(o))
        page = ctx.new_page()
        page.add_init_script(_INIT_JS)
        page.goto(login_url, wait_until="domcontentloaded")
        pre = {"session": _dump_session_storage(page), "local": _local_storage(page)}
        print("\n[auth init] Log in in the browser window. Detecting success automatically…", flush=True)
        # wait for login success: URL leaves the login path OR a JWT-looking value appears in storage
        try:
            page.wait_for_function(
                """lp => {
                    if (!location.pathname.includes(lp) || location.pathname === "/") {
                      // navigated away from login
                    }
                    const hasJwt = (s) => { for (let i=0;i<s.length;i++){const v=s.getItem(s.key(i));
                      if (v && /^eyJ[A-Za-z0-9_\\-]{4,}\\./.test(v)) return true;} return false; };
                    return (!location.pathname.includes(lp)) || hasJwt(sessionStorage) || hasJwt(localStorage);
                }""",
                arg=login_path, timeout=timeout_ms)
        except Exception:  # noqa: BLE001
            print("[auth init] timed out waiting for login — capturing current state anyway", flush=True)
        page.wait_for_load_state("networkidle", timeout=15000)
        post = {"session": _dump_session_storage(page), "local": _local_storage(page)}
        landed = page.url
        state = ctx.storage_state()
        browser.close()

    user_sel, pw_sel, submit_sel = infer_selectors(events)
    token = detect_token(pre, post)
    success_path = urlsplit(landed).path if urlsplit(landed).path not in ("", "/", login_path) else ""
    profile = build_profile(name, login_url, base, user_sel, pw_sel, submit_sel,
                            token, success_path, landed)

    # build a Session mirroring capture_scripted's shape so it can be used immediately
    session = Session(name=name, origin=base, storage_state=state,
                      session_storage=post["session"],
                      meta={"profile": name, "mode": "recorded",
                            "validity_url": base + success_path if success_path else landed,
                            "validity_marker": ""})
    from .profile import _from_dict
    _apply_bearer(session, _from_dict(profile))
    return profile, session
