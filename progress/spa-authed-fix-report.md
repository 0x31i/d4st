# d4st SPA authenticated-scan fixes

**Branch:** `feat/spa-authed-scan` (off `feat/auth-timeout-and-differential`)
**Commit:** `34274ca` — local only, not pushed.
**Tests:** full suite **246 passed, 1 skipped** (+15 new; baseline was 231/1).

## What changed (file / function)

### 1. `launch` rejected valid JWT-SPA sessions  → FIXED
- `d4st/auth/validity.py`: new `session_is_token_auth(session)` (bearer header or JWT-ish value
  in sessionStorage) + `is_session_valid(session, url, marker=None, render=None)`.
  - Explicit marker → honored (rendered if token-auth/render).
  - Token-auth + no marker → **valid on token presence** (the scanners replay the bearer; an
    expired token just yields 401s mid-scan). Still attempts a rendered probe for confidence,
    but only a *positive* bounce to a `/login` path marks it invalid — never an ambiguous SPA shell.
  - Non-token + no marker → unchanged raw 2xx/not-login heuristic.
- `d4st/cli.py launch`: uses `is_session_valid`; **drops the `marker or "Logout"` default**
  (that false-negatived every JWT-SPA). EHRM now scans authenticated **without `--force`**.

### 2. Authed crawl missed the SPA API surface  → FIXED
- `d4st/jsanalysis.py`: new `script_srcs(html, base, host)` (same-host `.js` bundles from the
  shell) + `mine_api_endpoints(target, cookie, headers, host)` — fetches the shell, finds the
  bundles, mines them via the existing `analyze_js`, returns absolute same-host `/api/*` URLs.
  Reuses the same route-mining the unauth path uses; best-effort, never raises.
- `d4st/orchestrator/workflow.py`: `WorkflowRunner.run(target, session=None, seed_urls=None)`
  now pre-seeds the frontier with `seed_urls` (after the target, before discovery).
- `d4st/cli.py launch`: new `--seed-url` (repeatable), `--seed-file`, `--no-js-mine`. When a
  session is supplied (authed scan), it auto-JS-mines the shell and seeds those endpoints, so
  detection (nuclei/zap/sqlmap) actually reaches the API surface Burp would.

### 3. `auth probe --json` emitted invalid JSON  → FIXED
- Root cause: `cli.py auth_probe` used `console.print(json.dumps(...))`; Rich line-wraps to
  terminal width (injecting newlines **inside** JSON string values) and interprets `[...]`
  markup → corrupt JSON when the body carries raw HTTP response text.
- `d4st/auth/differential.py`: new `AppProbe.as_dict()` centralizes serialization (incl.
  `raw_verdicts`, enum→str).
- `d4st/cli.py auth_probe`: now `click.echo(json.dumps(probe.as_dict(), indent=2))` (raw writer,
  `ensure_ascii` escapes everything). `launch --json` already used `click.echo` (fine).

## Tests added (15)
- `tests/test_validity.py` (9): token detection (header/JWT/cookie); `is_session_valid`
  branching incl. **the regression** (valid JWT session not rejected when render unavailable),
  positive-logout rejection, explicit-marker honored, cookie delegation.
- `tests/test_jsanalysis.py` (+3): `script_srcs` host/ext filtering; `mine_api_endpoints` glue
  (absolutize paths, drop off-host); no-scripts → empty.
- `tests/test_launch_seed.py` (3): frontier seeding, dedup/blank-skip, no-seed unchanged.
- `tests/test_auth_differential.py` (+1): `AppProbe.as_dict()` → `json.dumps`/`loads` round-trips
  with a nasty body (newlines, backslashes, markup, control chars).

## Deploy + re-run (for the parent — box is `fhcdast`, bind-mount `/home/dast/d4st/d4st`)
```bash
cd ~/OMNI/tmp/dast-ng && git checkout feat/spa-authed-scan
# back up, then rsync the package into the bind-mount (additive), clear bytecode:
ssh fhcdast "cp -a /home/dast/d4st/d4st /home/dast/d4st/d4st.bak.$(date +%s)"
rsync -az --exclude __pycache__ --exclude '*.pyc' d4st/ fhcdast:/home/dast/d4st/d4st/
ssh fhcdast "docker exec d4st sh -c 'find /app/d4st -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null; d4st auth probe --help >/dev/null && d4st launch --help | grep -i seed'"

# re-run authenticated EHRM (NO --force needed now; auto JS-mines the API surface):
ssh fhcdast "docker exec -d d4st sh -c '
  python3 /tmp/warm_btn.py >/dev/null 2>&1
  EHRM_USER=Dast EHRM_PASS=mtest d4st auth capture -p /tmp/ehrm3stage.yaml \
    -b https://ehrm3stage.fhcsd.org -o /app/sessions/ehrm_session.json -u Dast -w mtest --timeout 120000
  d4st launch -t https://ehrm3stage.fhcsd.org -s /app/sessions/ehrm_session.json \
    -w full --allow-active --json > /app/results/pipeline/ehrm_authed_full.json 2> /app/results/pipeline/ehrm_authed_full.log
'"
# watch: ssh fhcdast "tail -f /home/dast/d4st/results/pipeline/ehrm_authed_full.log"
```
Optionally add known API roots explicitly: `--seed-url https://ehrm3stage.fhcsd.org/api/...`
(repeatable) or `--seed-file`. Then Burp-compare the findings JSON.

## Note / caveat
`mine_api_endpoints` relies on the API routes being present in the JS bundles (true for the
EHRM/Angular family we probed). If a bundle lazy-loads route chunks the shell doesn't list,
some endpoints may be missed — `--seed-url`/`--seed-file` covers that gap. Deploy to the box was
NOT done here (parent is actively scanning on it); commands above are for the parent to run.
