# d4st scope-enforcement + ZAP fixes

**Branch:** `feat/scope-and-zap` (off `feat/spa-authed-scan`)
**Commit:** `8eb273b` — local only, not pushed, not deployed.
**Tests:** full suite **260 passed, 1 skipped** (+14 new; baseline 246/1). No regressions.

## BUG 1 — active/injection tools attacked OFF-SCOPE third-party hosts (FIXED)

Root cause: discovery (katana/JS-mining) drags in third-party resource URLs; the
`launch`/`WorkflowRunner` path never applied the scope filter the unauth path uses, so those
URLs entered the shared frontier and the detection tools (dalfox, sstimap, sqlmap, nuclei-dast…)
consumed them. Evidence from the authed EHRM run: dalfox "XSS" + sstimap SSTI fired at
`fonts.googleapis.com`, `docs.google.com/viewer`, `view.officeapps.live.com` — off-scope, both a
false-finding source and an ROE violation.

Fix (single chokepoint = the frontier, so every consumer is scoped):
- **`d4st/scope.py` (new)** — ONE canonical definition, extracted from the unauth path's inline
  logic: `scope_hosts(target, env=None)` (= `D4ST_SCOPE_HOSTS` comma-list, else the target host)
  and `in_scope(url, hosts)` (host == s or endswith "."+s → subdomain-aware; host-less/relative =
  in-scope; empty hosts = no restriction so a mis-derived scope never nukes the frontier) +
  `in_scope_pred(hosts)`.
- **`d4st/orchestrator/frontier.py`** — `Frontier(in_scope=<pred>)`: `add_url` refuses off-scope
  URLs and counts them (`off_scope_dropped()`, surfaced in `stats()`). `add_url(url, force=True)`
  bypasses the gate for the operator's explicit target.
- **`d4st/orchestrator/workflow.py`** — `WorkflowRunner.run` derives `scope_hosts(target)`, builds
  the Frontier with the predicate, adds the target `force=True`, and logs the dropped count
  (`[scope] restricted to <hosts>: dropped N off-scope URL(s)`).
- **`d4st/engagement.py`** — its inline `_scope`/`_in_scope` now call `d4st.scope` (one definition,
  no behavior change for the unauth path; absolute crawl URLs unaffected).

## BUG 2 — ZAP `ok=False | 0 alert(s), 0 url(s)` on the authed EHRM run (FIXED + diagnosed)

Two problems:
1. **Auth gap (the likely coverage cause):** the adapter injected only the **Cookie** header via a
   ZAP replacer. EHRM auth is a **bearer JWT** (no auth cookie), so ZAP crawled/scanned
   **logged-out** → little/no surface.
   Fix: `_auth_config(cookie, headers)` now adds one replacer rule per **non-cookie session header**
   (`Authorization: Bearer …`, etc.); `build_zap_args(..., headers=)` threads them; `run()` pulls
   them via the new `session_util._session_headers()`. Bearer-only sessions now scan authenticated.
2. **Swallowed failure reason:** `ok` was `rc in (0,1,2)` and the note was always
   "`N alert(s), M url(s)`", so a real error (rc≥3 / ZAP couldn't start / AJAX browser missing /
   target unreachable) looked identical to a clean empty run.
   Fix: `run()` now distinguishes — **no report produced** → `ok=False` with
   `"no report produced (zap rc=<rc>): <stderr tail>"`; **timeout** → explicit
   `"TIMEOUT after <n>s (killed)…"`; **report produced** → `ok=True` even with 0 alerts (a clean
   result), appending `"(warning: zap rc=<rc>)"` if the code was anomalous.

Root-cause hypothesis for *this* run (needs a live ZAP to confirm): either (a) ZAP ran logged-out
(cookie-only) and the traditional+AJAX spider found ~nothing on the SPA shell, or (b) it exceeded
the workflow `timeout: 1800` and was killed, or (c) the AJAX `firefox-headless` browser wasn't
available in the container → rc=3, empty report. With this change the next run's note will state
which. Verify on the box with: `d4st doctor` (checks ZAP + browser) and re-reading the tools note.

## Polish — `--json` stdout pollution (FIXED)
`launch` printed `session valid: …` to stdout, prepending non-JSON to the `--json` findings file
(the parent had to strip the first line). Now routed to **stderr** in `--json` mode
(`d4st/cli.py`), so `--json` stdout is pure JSON.

## Files changed
- NEW `d4st/scope.py`, NEW `tests/test_scope.py`
- `d4st/orchestrator/frontier.py`, `d4st/orchestrator/workflow.py`
- `d4st/orchestrator/adapters/zap.py`, `d4st/orchestrator/adapters/session_util.py`
- `d4st/cli.py`, `d4st/engagement.py`, `tests/test_zap_ajax.py`

## Tests (14 new)
- `test_scope.py` (10): scope_hosts default/env/subdomain; in_scope excludes the 3 real off-scope
  hosts, keeps in-scope, host-less/empty semantics; Frontier drops off-scope + counts, `force`
  bypass for target, no-predicate legacy behavior; **end-to-end** WorkflowRunner test proving a
  discovery adapter's off-scope URLs never reach the detection adapter's target list.
- `test_zap_ajax.py` (+4): Authorization injected alongside Cookie; bearer-only session still
  injects auth; no double-Cookie; `run()` surfaces rc+reason when no report; clean 0-alert = ok.

## Deploy (for the parent — box `fhcdast`, bind-mount `/home/dast/d4st/d4st`)
```bash
cd ~/OMNI/tmp/dast-ng && git checkout feat/scope-and-zap
ssh fhcdast "cp -a /home/dast/d4st/d4st /home/dast/d4st/d4st.bak.scopezap.$(date +%s)"
rsync -az --exclude __pycache__ --exclude '*.pyc' d4st/ fhcdast:/home/dast/d4st/d4st/
ssh fhcdast "docker exec d4st sh -c 'find /app/d4st -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null; python3 -c \"import d4st.scope, d4st.orchestrator.workflow, d4st.orchestrator.adapters.zap; print(\\\"ok\\\")\"'"
# then re-run authed EHRM; the frontier will log '[scope] restricted to ehrm3stage.fhcsd.org: dropped N off-scope'
# and the ZAP tools-note will state the real reason if it still fails.
```

## Out of scope (noted, not changed)
- A live ZAP run is needed to confirm which ZAP root cause applies; the adapter will now report it.
- `--seed-url`/`--seed-file` seeds are also scope-filtered now (off-scope seeds dropped) — if an
  engagement ever intentionally seeds a different in-scope host, set `D4ST_SCOPE_HOSTS` to include it.
