"""DOM-free token minting for canvas / token-SPA apps (Flutter CanvasKit, Angular, React).

A CanvasKit app paints its entire UI — login form included — onto a <canvas>, so there is no
DOM <form>/<input>/<button> for the selector recorder (recorder.py) or the scripted form filler
(capture_scripted) to drive, and `document.body.innerText` is empty so a text validity marker
never matches. But the authentication itself is an ordinary XHR to an `/api/.../AuthUser` endpoint
that drops a JWT into sessionStorage. This module replays THAT request directly — no selectors, no
clicks, no human — so a fresh token can be minted on demand and unattended, as many times as the
scan needs (JWTs expire ~30 min into a long engagement).

Two replay paths, chosen by `auth_api.cred_style`:
  - plaintext-query | json-body | form-urlencoded : pure httpx. Build the request from a template
    with {user}/{pass}, send it, pull the token out of the JSON response (token_json_path). No
    browser process — the robust, fast path for unattended re-auth.
  - encrypted-paramtoken : the app encrypts creds client-side into an opaque `paramToken` (often a
    timestamped/nonced blob, so a captured blob is NOT replayable). We load the app headless so its
    own JS crypto bundle is present, call the app's encrypt function with fresh creds via
    page.evaluate, fetch AuthUser in-page, and read the JWT back out of sessionStorage. Borrows the
    app's crypto instead of reversing it, so it stays correct as the app evolves.

The result is a Session (cookies + sessionStorage + an Authorization header), identical in shape to
what capture.py produces, so everything downstream (_apply_bearer / set_auth_header / harvest) is
unchanged.

Learn the recipe ONCE from a real login (DevTools -> Network -> the AuthUser request -> Copy as
fetch) and encode it in the profile's `auth_api` block; the minter replays it thereafter.
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import quote, urlsplit

from .profile import AuthProfile
from .session import Session

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.?[A-Za-z0-9_\-]*")


def _dig(obj, path: str):
    """Pull a value out of a decoded JSON response by a dotted path (e.g. 'data.accessToken').
    Returns None if any hop is missing. A bare '' path returns the whole object."""
    if not path:
        return obj
    cur = obj
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
                continue
            except (ValueError, IndexError):
                return None
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _find_jwt(obj) -> str | None:
    """Last-resort token discovery: walk a decoded JSON body for the first eyJ… JWT value.
    Used when the profile doesn't pin an exact token_json_path."""
    if isinstance(obj, str):
        m = _JWT_RE.search(obj)
        return m.group(0) if m else None
    if isinstance(obj, dict):
        for v in obj.values():
            t = _find_jwt(v)
            if t:
                return t
    elif isinstance(obj, list):
        for v in obj:
            t = _find_jwt(v)
            if t:
                return t
    return None


def _subst(template, user: str, pw: str):
    """Recursively substitute {user}/{pass} into a str / dict / list request template."""
    if isinstance(template, str):
        return template.replace("{user}", user).replace("{pass}", pw)
    if isinstance(template, dict):
        return {k: _subst(v, user, pw) for k, v in template.items()}
    if isinstance(template, list):
        return [_subst(v, user, pw) for v in template]
    return template


def _mint_httpx(profile: AuthProfile, base: str, user: str, pw: str, *,
                timeout: float, verify: bool) -> Session:
    """Replay a plaintext / json / form login with httpx and read the token from the response."""
    import httpx

    api = profile.auth_api
    url = profile.fmt(api["url"], base)
    method = (api.get("method") or "GET").upper()
    style = api.get("cred_style", "plaintext-query")
    req = _subst(api.get("request", {}), user, quote(pw, safe="") if style == "plaintext-query" else pw)
    headers = dict(api.get("headers", {}))

    kwargs: dict = {"headers": headers, "timeout": timeout}
    if style == "plaintext-query":
        # creds go in the query string; {user}/{pass} were already url-encoded above
        qs = req.get("query", "") if isinstance(req, dict) else str(req)
        url = url + (("&" if "?" in url else "?") + qs if qs else "")
    elif style == "json-body":
        kwargs["json"] = req.get("json", req) if isinstance(req, dict) else req
    elif style == "form-urlencoded":
        kwargs["data"] = req.get("form", req) if isinstance(req, dict) else req
    else:
        raise RuntimeError(f"cred_style {style!r} is not an httpx style; use the browser path")

    with httpx.Client(verify=verify, follow_redirects=True) as c:
        r = c.request(method, url, **kwargs)

    try:
        body = r.json()
    except Exception:  # noqa: BLE001 - non-JSON body; fall back to regex over text
        body = r.text

    tok = profile.token or {}
    path = api.get("token_json_path")
    raw_tok = None
    if path is not None:
        raw_tok = _dig(body, path)
        if isinstance(raw_tok, str):
            m = _JWT_RE.search(raw_tok)
            raw_tok = m.group(0) if m else raw_tok
    if not raw_tok and path is None:
        raw_tok = _find_jwt(body)

    host = urlsplit(base).hostname or ""
    cookies = [{"name": ck.name, "value": ck.value, "domain": ck.domain or host,
                "path": ck.path or "/"} for ck in r.cookies.jar]

    # Success-by-status path: some apps authenticate but issue no token in the login response (the
    # session rides a cookie, or a separately-established custom header). Treat the login as proven
    # when the status matches success_status (default 200/202) and any success_marker is in the body
    # — a failed login returns a different status/message, which keeps this honest.
    if not raw_tok:
        ok_status = api.get("success_status")
        marker = api.get("success_marker")
        status_ok = (r.status_code == ok_status) if ok_status else (r.status_code in (200, 202))
        marker_ok = (marker in (r.text or "")) if marker else True
        if ok_status is not None and status_ok and marker_ok:
            sess = Session(name=profile.name, origin=base,
                           storage_state={"cookies": cookies}, session_storage={},
                           meta={"profile": profile.name, "mode": "mint-httpx-nostatus",
                                 "login_status": r.status_code,
                                 "login_proof": (r.text or "")[:200],
                                 "validity_url": _validity_api(profile, base)})
            # attach a static session header if the profile names one via env (token not in body)
            static = os.environ.get(tok.get("static_env", "")) if tok.get("static_env") else None
            if static:
                sess.headers[tok.get("header", "Authorization")] = f"{tok.get('scheme', '')}{static}"
            return sess
        snippet = (r.text or "")[:200].replace("\n", " ")
        raise RuntimeError(
            f"minter: login not confirmed (HTTP {r.status_code}; style={style}; "
            f"token_json_path={path!r}; success_status={ok_status}). Body starts: {snippet!r}")

    sess = Session(name=profile.name, origin=base,
                   storage_state={"cookies": cookies},
                   session_storage={tok.get("key", "accessToken"): raw_tok} if tok.get("key") else {},
                   meta={"profile": profile.name, "mode": "mint-httpx",
                         "validity_url": _validity_api(profile, base), "status": r.status_code})
    sess.headers[tok.get("header", "Authorization")] = f"{tok.get('scheme', 'Bearer ')}{raw_tok}"
    return sess


def _mint_browser(profile: AuthProfile, base: str, user: str, pw: str, *,
                  timeout_ms: int, verify: bool) -> Session:
    """Encrypted-paramtoken path: load the app headless so its JS crypto is available, encrypt the
    creds with the app's OWN function, fetch AuthUser in-page, read the JWT from sessionStorage."""
    from playwright.sync_api import sync_playwright

    api = profile.auth_api
    tok = profile.token or {}
    tkey = tok.get("key") or "accessToken"
    login_url = profile.fmt(profile.login_url, base)
    api_url = profile.fmt(api["url"], base)
    method = (api.get("method") or "GET").upper()
    encrypt_js = api.get("encrypt_js")            # in-page expr: a fn (user,pass) -> paramToken
    param = api.get("paramtoken_param", "paramToken")
    store_obj = "localStorage" if str(tok.get("storage", "session")).startswith("local") else "sessionStorage"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--ignore-certificate-errors"] if not verify else [])
        ctx = browser.new_context(ignore_https_errors=not verify)
        page = ctx.new_page()
        page.goto(login_url, wait_until="networkidle", timeout=timeout_ms)
        # Encrypt creds with the app's own routine, then make the exact AuthUser fetch the app makes.
        result = page.evaluate(
            """async (a) => {
                 let pt;
                 try { pt = a.enc ? (new Function('u','p','return (' + a.enc + ')(u,p)'))(a.user, a.pw) : null; }
                 catch (e) { return {error: 'encrypt_js failed: ' + e}; }
                 const sep = a.url.includes('?') ? '&' : '?';
                 const url = pt != null ? a.url + sep + a.param + '=' + encodeURIComponent(pt) : a.url;
                 let r;
                 try { r = await fetch(url, {method: a.method, credentials: 'include'}); }
                 catch (e) { return {error: 'fetch failed: ' + e}; }
                 let body = ''; try { body = await r.text(); } catch (e) {}
                 return {status: r.status, body: body};
             }""",
            {"url": api_url, "method": method, "enc": encrypt_js, "param": param,
             "user": user, "pw": pw})
        if isinstance(result, dict) and result.get("error"):
            browser.close()
            raise RuntimeError(f"minter(browser): {result['error']}")
        # Give the app a beat to persist the JWT, then read it back.
        try:
            page.wait_for_function(
                "a => !!window[a.s] && !!window[a.s].getItem(a.k)",
                arg={"s": store_obj, "k": tkey}, timeout=8000)
        except Exception:  # noqa: BLE001
            pass
        sstore = page.evaluate(
            "() => { const o={}; for (let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i);o[k]=sessionStorage.getItem(k);} return o; }"
        ) or {}
        state = ctx.storage_state()
        browser.close()

    raw_tok = sstore.get(tkey)
    if not raw_tok and store_obj == "localStorage":
        for o in state.get("origins", []):
            for item in o.get("localStorage", []):
                if item.get("name") == tkey:
                    raw_tok = item.get("value")
    if not raw_tok:
        raise RuntimeError(
            f"minter(browser): no {tkey!r} in {store_obj} after AuthUser "
            f"(status={result.get('status') if isinstance(result, dict) else '?'}). "
            f"Check encrypt_js / token.key.")

    sess = Session(name=profile.name, origin=base, storage_state=state, session_storage=sstore,
                   meta={"profile": profile.name, "mode": "mint-browser",
                         "validity_url": _validity_api(profile, base)})
    sess.headers[tok.get("header", "Authorization")] = f"{tok.get('scheme', 'Bearer ')}{raw_tok}"
    return sess


def _validity_api(profile: AuthProfile, base: str) -> str:
    v = (profile.validity or {}).get("api") or ""
    return profile.fmt(v, base) if v else ""


def mint_token(profile: AuthProfile, base: str | None = None, *,
               username: str | None = None, password: str | None = None,
               timeout_ms: int = 30000, verify: bool = False) -> Session:
    """Mint a fresh auth session by replaying the app's login XHR (no DOM, no human).

    Dispatches to the httpx path (plaintext/json/form creds) or the headless-browser path
    (encrypted paramToken). Raises RuntimeError with a diagnostic on failure.
    """
    if not profile.auth_api or not profile.auth_api.get("url"):
        raise RuntimeError(
            f"profile {profile.name!r} has no auth_api.url — this is a DOM-form profile, not a "
            f"spa-token-api recipe. Record the AuthUser request and add an auth_api block.")
    base = profile.resolve_base(base)
    user, pw = profile.creds(username, password)
    if not user:
        raise RuntimeError(
            f"profile {profile.name!r}: no username (set {profile.username_env or 'the creds env'} "
            f"or pass --username)")
    style = profile.auth_api.get("cred_style", "plaintext-query")
    known = {"plaintext-query", "json-body", "form-urlencoded", "encrypted-paramtoken"}
    if style not in known:
        raise RuntimeError(
            f"profile {profile.name!r}: auth_api.cred_style={style!r} is not filled in. Record the "
            f"AuthUser request (DevTools -> Copy as fetch) and set it to one of: {', '.join(sorted(known))}.")
    if style == "encrypted-paramtoken":
        return _mint_browser(profile, base, user, pw, timeout_ms=timeout_ms, verify=verify)
    return _mint_httpx(profile, base, user, pw, timeout=timeout_ms / 1000.0, verify=verify)
