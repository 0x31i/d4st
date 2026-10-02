# D4ST (FHC) tests + upgrades — agent report (2026-10-01)

Branch: **`feat/auth-timeout-and-differential`** · commit **`0fbd888`** · author `eli <...0x31i...>`
(local only — NOT pushed, not deployed; no Claude trailer.)

## What changed

1. **`--timeout` landed in the repo** (was live-only on the FHC box, bind-mount).
   `d4st/cli.py auth capture`: `--timeout/timeout_ms` (default 30000, int) → threaded into
   `capture_scripted(..., timeout_ms=...)`. Fixes EHRM-style slow cold-start blowing the 30s default.

2. **Generalized credential differential probe** — new `d4st/auth/differential.py` + CLI
   `d4st auth probe`. Promotes the scratchpad prototypes (inspect_webforms / debug2 / final_diff /
   raw_replay2) into a reusable, hostname-agnostic capability:
   - Submits a **deliberately non-existent baseline username** next to the real creds; identical
     server response ⇒ **NOT_PROVISIONED**. Verdicts: `LOGGED_IN` / `NOT_PROVISIONED` /
     `ACCOUNT_EXISTS_REFUSED` (locked/expired/…) / `DISTINCT_REJECTION` / `INDETERMINATE`.
   - **Browser lens** (Playwright, lazy): discovers login form + the real auth API call (incl.
     JS onclick → GET-creds-in-URL and SPA token-in-storage success), screenshots each attempt.
   - **Raw lens** (httpx): browser-independent replay of the discovered endpoint for corroboration;
     warns + marks unreliable when client-side password hashing is detected.
   - Read-only, lockout-safe (≤1 attempt per cred/lens; a non-existent account has no lockout counter).
   Usage: `d4st auth probe -t <login-url> -u <user> [-u <user2>] -w <pass> [--token-key JWTToken]
   [--timeout 120000] [-o evidence/] [--json]`

3. **Profile templates**: `d4st/auth/profiles/webforms-authuser.example.yaml` (ASP.NET WebForms
   onclick→AuthUser-GET family) + annotated `spa-token.example.yaml` with cold-start/`--timeout`
   and `formcontrolname` guidance. Placeholders only — no client hostnames.

## Tests
- Full suite: **231 passed, 1 skipped** (the skip needs a live browser). Was 220 before; +11 new.
- New `tests/test_auth_differential.py`: classifier cases (incl. the real bugs it caught — see below)
  + raw lens via `httpx.MockTransport` (all-rejected ⇒ not-provisioned; real login ⇒ logged-in;
  param substitution leaves `UserId=0` intact).

## Two real bugs the tests caught (fixed)
- Substring false-match: `"blocked"` contains `"locked"` → would misread an IP-block as
  "account locked". Now word-boundary matched.
- Field heuristic: `UserId` matched the `user` hint and got overwritten with the username. Now
  `*Id` params are excluded, so bookkeeping params (`UserId=0`, `intUserId=0`) stay intact — this
  would have corrupted the raw replay against the real FHC AuthUser endpoints.

## Still blocked on the VPN (cannot run locally)
- **D1** unauth scan of all 30 staging apps, **D2** authenticated EHRM scan to exercise the coverage
  upgrades, and the **live D3** run of `auth probe` across every FHC login page. All require the
  Surface FortiClient tunnel back up (d4st box `192.168.50.128` unreachable now). The code to do
  D3 at scale is ready; the EHRM live `--timeout` path is already proven on-box.

## Not done / deferred
- No push/deploy (by directive). To ship: merge `feat/auth-timeout-and-differential` → main and
  `git pull` on the FHC box (bind-mount) to replace the hand-patched cli.py there.
- The ASP.NET `__doPostBack` crawler (separate deferred item) was out of scope for this pass.
