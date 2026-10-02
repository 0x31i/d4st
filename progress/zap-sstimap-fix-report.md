# d4st — ZAP rc=3 report fix + sstimap false-positive fix

**Branch:** `feat/zap-report-fix` (off `feat/scope-and-zap`) · **Commit:** `8d1c2c3` · local only, not pushed/deployed.
**Tests:** full suite **262 passed, 1 skipped** (parent was 260/1; +2 ZAP tests; sstimap test rewritten).

## BUG A — ZAP produced no report (`ok=False rc=3`, "A file based operation failed") — FIXED
**Root cause:** `ZapAdapter.run` created a `tempfile.mkdtemp()` workdir but **never ran ZAP in it**.
`_exec` invoked `zap-full-scan.py -J report.json` with **no cwd and no env**, so:
- `-J report.json` was written relative to d4st's own cwd (often not writable → nothing found), and
- ZAP's home (`~/.ZAP` session DB + config) resolved to a home that may be unwritable in the container
  → ZAP dies with rc=3 "A file based operation failed" before writing anything.

**Fix** (`d4st/orchestrator/adapters/zap.py`, `d4st/orchestrator/adapters/base.py`):
- `base._exec` gained optional `cwd` / `env` params (default `None` → unchanged for every other caller).
- ZAP now runs with `cwd=<mkdtemp workdir>` and `env=HOME=<workdir>`, so both the report and ZAP's
  home/session files land in a guaranteed-writable dir (a fresh `/tmp/zap_*`).
- Report discovery now checks `workdir/report.json`, legacy `/zap/wrk/report.json`, and the launcher cwd.
- Failure note now joins the **last 4 non-empty lines** of ZAP stdout/stderr (was 1), so the real reason
  (file-op / browser-missing / startup) is visible: `no report produced (zap rc=N): <...tail...>`.

**Verify on the box (after deploy):**
1. `docker exec d4st d4st doctor` (ZAP + firefox-headless present).
2. `docker exec d4st d4st launch -t https://ehrm3stage.fhcsd.org -s /app/sessions/ehrm_session.json -w full --allow-active --json >/tmp/z.json 2>/tmp/z.log`
   then check the tools table shows `zap ok=True | N alert(s)` (or, if still failing, the note now carries
   the precise multi-line ZAP error to act on). The writable-workdir+HOME change addresses the file-op rc=3;
   if a *different* residual error surfaces (e.g. missing AJAX browser), the richer note will name it.

## BUG B — sstimap evidence-less false-positive SSTI — FIXED
**Root cause:** `parse_sstimap` emitted a finding whenever the output merely contained
`template injection` **or** `Engine: <word>` **or** `injection point` — all of which appear in SSTImap's
banner/progress text on **every** run. Result: a phantom SSTI with no URL/param/payload and an engine
that changed run-to-run (`Python` then `Nunjucks` — impossible on an ASP.NET app).

**Fix** (`d4st/orchestrator/adapters/injection2.py`):
- Gate strictly on SSTImap's **confirmation** marker: `identified the following injection point`
  (printed only on a real hit). Unconfirmed/progress output → `[]`, no finding.
- On a confirmed hit, capture **url** (now passed through from the `_probe` caller), **param**
  (`Query/Form parameter:`), **payload** (`Injection:`), **engine**, `severity: high`,
  `confidence: confirmed`, and a 400-char **evidence** excerpt — so it's actionable + scope-checkable.

## Tests
- `tests/test_roster_adapters.py::test_parse_sstimap` rewritten: banner/progress + "couldn't find" →
  `[]`; a confirmed block → one finding with url/param/payload/engine/evidence/high/confirmed.
- `tests/test_zap_ajax.py` +2: ZAP runs with cwd + `HOME` set to a writable dir and finds the report it
  writes there; and a no-report run surfaces the real multi-line error + `rc=3`.

## Files changed
- `d4st/orchestrator/adapters/base.py` — `_exec(cwd=, env=)` (additive)
- `d4st/orchestrator/adapters/zap.py` — run in writable workdir+HOME, multi-path report discovery, richer error note
- `d4st/orchestrator/adapters/injection2.py` — `parse_sstimap` confirmation-gating + evidence capture; `_probe` passes `url`
- `tests/test_roster_adapters.py`, `tests/test_zap_ajax.py`

## Deploy (for the parent — box `fhcdast`, bind-mount `/home/dast/d4st/d4st`)
```bash
cd ~/OMNI/tmp/dast-ng && git checkout feat/zap-report-fix
ssh fhcdast "cp -a /home/dast/d4st/d4st /home/dast/d4st/d4st.bak.zap.$(date +%s)"
rsync -az --exclude __pycache__ --exclude '*.pyc' d4st/ fhcdast:/home/dast/d4st/d4st/
ssh fhcdast "docker exec d4st sh -c 'find /app/d4st -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null; python3 -c \"import d4st.orchestrator.adapters.zap, d4st.orchestrator.adapters.injection2; print(\\\"ok\\\")\"'"
# then re-run the authed EHRM scan and confirm `zap ok=True` in the tools table.
```

## Out of scope (noted, not done)
- `launch` crawl exits at the round-cap (3) with "new surface still pending" — raising it would give a
  more exhaustive authed EHRM pass; left for a separate change.
