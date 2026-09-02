# d4st observability console — build plan

Status: **design locked, build not started.** This plan turns the file-based scan output into
a fast, DB-backed observability console that surfaces **all** collected probes and data, while
leaving the CLI (the primary interface) completely untouched.

## Locked decisions

- **Store: SQLite.** Embedded, zero-ops, single file. Keeps d4st a `pip install && d4st
  serve` appliance with no external services. Postgres was rejected as too heavy for this
  data scale (hundreds of rows/scan) and deployment model (single self-hosted appliance).
  A thin data-access layer keeps the engine swappable if it ever needs Postgres.
- **No grade.** This is a findings-observability tool, not a scorecard. The A–F letter grade
  and "posture" verdict are removed from the console *and* the standalone report (done). The
  header shows a **severity donut** (total findings, ring proportioned by the severity mix)
  and a neutral count headline instead.
- **Frontend: upgrade the existing vanilla-JS SPA** (`d4st/webui.py`), not a React fork.
  No Node/Vite build step; stays one Python-served artifact. Data scale doesn't need TanStack
  virtualization. (Revisit only if we later want exact ASM-NG table interactions.)
- **Identity preserved.** d4st's terminal/amber/monospace look stays — distinct from
  ASM-NG, same product family.
- **CLI is the driver; the DB is a read/observe spine.** Ingest happens at scan-end (and on
  demand for existing JSONs). Nothing about `launch` / `engagement` / `auth` / `score`
  changes.

## Data contract (from the code, unchanged by this work)

The whole pipeline already produces one engagement result dict (`engagement.run_engagement`):
`findings[]`, `urls[]`, `targets`, `policy`, `health{stage,halted,sqlmap_level_used,events}`,
`zap`, `chain[]`, `warnings[]`, `session{keeper,reauths,authed_at_end}`.

Each `Finding` (`engagement.py` dataclass): `tool, category, url, param, method, evidence,
verified, verify_note, evidence_log[], payload, detection, confidence, raw_output, repro`.
Severity/CWE/OWASP/title/fix are **not** stored — they're a render-time join on `category`
via `report.VULN_META`. The ingest denormalizes that join into the DB so the UI never computes it.

Each `evidence_log` entry is an exchange: `{label, request{method,url,headers,body},
response{status,headers,elapsed_ms,size,body,truncated}}`. This is the evidence contract.

## SQLite schema (6 tables, all indexed on scan_id + filter columns)

```sql
-- one row per scan
CREATE TABLE scans (
  id            TEXT PRIMARY KEY,         -- scan_id (slug or uuid)
  target        TEXT,
  profile       TEXT,                     -- policy.name
  created_at    INTEGER,                  -- unix ts (ingest time / scan end)
  status        TEXT,                     -- 'complete' | 'in-progress' | 'error'
  app_type      TEXT,                     -- fingerprint note (mpa/spa, server banner)
  urls_count    INTEGER,
  targets_count INTEGER,
  exchanges_count INTEGER,
  n_findings    INTEGER,
  sev_critical INTEGER, sev_high INTEGER, sev_medium INTEGER, sev_low INTEGER, sev_info INTEGER,
  session_keeper INTEGER, reauths INTEGER, authed_at_end INTEGER, halted INTEGER, stage INTEGER,
  sqlmap_level INTEGER,
  policy_json  TEXT                       -- full policy blob for the Overview drill
  -- NOTE: no grade / posture columns, by decision.
);

CREATE TABLE findings (
  id           INTEGER PRIMARY KEY,
  scan_id      TEXT REFERENCES scans(id),
  dedup_key    TEXT,                      -- (category, url_path, param)
  tool         TEXT,
  category     TEXT,
  url          TEXT,
  url_path     TEXT,
  param        TEXT,
  method       TEXT,
  evidence     TEXT,                      -- reasoning
  payload      TEXT,
  detection    TEXT,
  confidence   TEXT,                      -- confirmed|firm|tentative
  verified     INTEGER,                   -- 1 true / 0 false / NULL unverified
  verify_note  TEXT,
  repro        TEXT,
  raw_output   TEXT,
  -- denormalized enrichment (joined from VULN_META at ingest):
  severity     TEXT, cwe TEXT, owasp TEXT, vtitle TEXT, vfix TEXT,
  -- analyst write-back:
  triage_status TEXT DEFAULT 'open',      -- open|confirmed|false_positive|accepted
  analyst_note  TEXT,
  updated_at    INTEGER
);
CREATE INDEX ix_find_scan ON findings(scan_id);
CREATE INDEX ix_find_sev  ON findings(scan_id, severity);
CREATE INDEX ix_find_cat  ON findings(scan_id, category);
CREATE INDEX ix_find_tool ON findings(scan_id, tool);

CREATE TABLE evidence (            -- exploded evidence_log, one row per exchange
  id           INTEGER PRIMARY KEY,
  finding_id   INTEGER REFERENCES findings(id),
  scan_id      TEXT REFERENCES scans(id),
  seq          INTEGER,
  label        TEXT,
  req_method   TEXT, req_url TEXT, req_headers TEXT, req_body TEXT,
  resp_status  INTEGER, resp_headers TEXT, resp_elapsed_ms INTEGER, resp_size INTEGER,
  resp_body    TEXT, truncated INTEGER
);
CREATE INDEX ix_ev_finding ON evidence(finding_id);
CREATE INDEX ix_ev_scan    ON evidence(scan_id);

CREATE TABLE frontier_urls (       -- crawl reach observability
  id            INTEGER PRIMARY KEY,
  scan_id       TEXT REFERENCES scans(id),
  url           TEXT,
  discovered_by TEXT,              -- katana|feroxbuster|gau|x8|linkharvest|zap
  param_count   INTEGER,
  is_target     INTEGER,           -- became an injection target
  hit_by        TEXT               -- 'category · tool' if a finding landed here, else NULL
);
CREATE INDEX ix_fr_scan ON frontier_urls(scan_id);

CREATE TABLE probes (              -- the engine chain: what each tool did
  id            INTEGER PRIMARY KEY,
  scan_id       TEXT REFERENCES scans(id),
  engine        TEXT,
  ran           INTEGER,
  expected      INTEGER,
  note          TEXT,
  findings_count INTEGER,
  command       TEXT,              -- exact command line (when available)
  raw_tail      TEXT               -- tail of native output for drill-in
);
CREATE INDEX ix_pr_scan ON probes(scan_id);

CREATE TABLE events (              -- health + session timeline (also the live feed)
  id       INTEGER PRIMARY KEY,
  scan_id  TEXT REFERENCES scans(id),
  seq      INTEGER,
  ts       INTEGER,               -- relative or absolute
  kind     TEXT,                  -- stage|reauth|halt|session|note
  stage    TEXT,
  message  TEXT,
  data_json TEXT
);
CREATE INDEX ix_ev2_scan ON events(scan_id);
```

New module: `d4st/store.py` — the DAL. `connect()`, `init_schema()`, `ingest(result, scan_id)`,
and typed query helpers (`list_scans`, `scan_overview`, `query_findings(filters, sort, page)`,
`finding_detail`, `frontier`, `probes`, `events`, `set_triage`, `set_note`). Uses stdlib
`sqlite3` with `row_factory`; WAL mode for concurrent read during a live-scan write.

## Ingest

- **Auto at scan-end**: after `run_engagement` returns, the CLI (`engagement` command) calls
  `store.ingest(result, scan_id)` when a `D4ST_DB` path is configured (default
  `~/.d4st/d4st.db`). Purely additive — does not change existing `-o out.json` behavior.
- **On demand**: `d4st ingest <scan.json> [--id NAME]` for the pile of existing result
  JSONs (`results*/`, `~/.d4st/scans/*.json`). Idempotent: re-ingesting a scan_id replaces
  its rows (delete+reinsert), carrying analyst `triage_status`/`analyst_note` forward by
  `dedup_key` — same carry-forward pattern as ASM-NG's findings store.
- **Enrichment at ingest**: join `category -> VULN_META` once, write severity/cwe/owasp/
  vtitle/vfix onto each finding row. (VULN_META stays the source of truth; re-ingest picks up
  changes.)

## API (FastAPI, expands `d4st/server.py`)

Read:
- `GET /api/scans` — list (id, target, created_at, status, counts, sev mix) for the sidebar.
- `GET /api/scans/{id}` — Overview: coverage, session health, policy, engine summary.
- `GET /api/scans/{id}/findings?severity=&category=&tool=&verified=&triage=&q=&sort=&dir=&page=`
  — paginated/filtered/sorted findings (indexed query, instant).
- `GET /api/findings/{fid}` — full detail incl. exploded evidence exchanges.
- `GET /api/scans/{id}/frontier?is_target=&hit=&q=` — attack-surface table.
- `GET /api/scans/{id}/probes` — engine chain.
- `GET /api/scans/{id}/events` — timeline.
- `GET /api/scans/{id}/evidence?q=` — global exchange browser.
- `GET /api/scans/{id}/raw?kind=&source=&type=&method=&severity=&status=&url=&param=&detail=&q=&sort=&dir=&page=`
  — the RAW DATA grid: a UNION of every collected record (finding/url/probe/exchange/event)
  projected to one common column set. Backed by a SQLite VIEW `raw_records` (UNION ALL across
  the tables, each row tagged with `kind` + normalised columns). Every column filters
  independently, stacked with the global search — the ASM-NG RAW DATA experience.
- `GET /api/report/{id}` — existing self-contained HTML report (unchanged path).

Write-back (the "manage" part):
- `POST /api/findings/{fid}/triage` — {status} → open|confirmed|false_positive|accepted.
- `POST /api/findings/{fid}/note`   — {note}.
- (write endpoints only mutate the analyst columns; scan data is immutable.)

Live:
- `GET /api/scans/{id}/live` — if a `D4ST_PROGRESS_FILE` exists for an in-progress scan,
  stream/poll its checkpoint (status, last_stage, elapsed, counts, timeline) so the Timeline
  and header update in real time. Poll first (simple, robust); SSE optional later.

Still no auth by default (localhost appliance); a config flag can gate it for networked deploys.

## Frontend (upgrade `d4st/webui.py` SPA)

Seven surfaces, matching the approved mockup (terminal/amber, severity donut, no grade):
1. **Overview** — coverage card + session-health card + policy + engine summary. Stats are
   drill-ins into the relevant filtered table.
2. **Findings** — the interactive table: sortable headers, severity filter pills, live search;
   row-expand shows reasoning, payload, request/response proof panes, remediation, and the
   triage/note write-back buttons. Backed by the indexed query endpoint.
3. **Attack Surface** — the frontier: every URL, discovered-by, param count, is-target,
   hit-by. Answers "did we actually cover the app?"
4. **Engines** — per-engine ran/expected, note, findings count, command, raw tail. Zero-finding
   engine reads as "ran clean"; expected-but-missing reads red.
5. **Timeline** — the event stream (stages, re-auths, halts). Live view for in-progress scans.
6. **Evidence** — global browser of every captured exchange.
7. **Raw Data** — the ASM-NG RAW DATA power-grid: every collected record (finding/url/probe/
   exchange/event) unified into one flat table with **per-column Excel-style filtering**
   (dropdowns for fixed sets: kind/source/method/severity/status; text-contains for freeform:
   type/url/param/detail), stacked with a global search and sortable headers, plus a
   clear-filters reset. Backed by the `raw_records` UNION view. Row → jumps to its home tab.

Implementation notes: keep the SPA dependency-free; add a small client-side table helper
(sort/filter/paginate against the API), a generic per-column filter row (auto-populated
dropdowns from distinct values + text inputs) for the Raw Data grid, a themed detail/expand,
and a poll loop for live scans. Reuse the existing `proof()` exchange renderer.

## Phasing (this is DAST plan Phase 6, sub-phased)

- **C1 — Store + ingest. ✅ DONE.** `d4st/store.py` (schema, DAL, `ingest()` w/ VULN_META
  denorm + carry-forward by dedup_key + read helpers), `d4st ingest` command, auto-ingest
  hook at scan-end (`D4ST_NO_INGEST=1` opts out). Backfilled dvwa/vampi/dvwa-demo into
  `~/.d4st/d4st.db`. Verified: counts match source (dvwa 68 findings / 130 urls / 52
  exchanges), re-ingest idempotent, analyst triage+note carried forward, frontier `hit_by`
  precise (full-url match, not path — avoids the ASM-NG path-collision trap). Tests:
  `tests/test_store.py` (3 pass). Note: frontier `discovered_by`/`is_target` and health
  `events` are sparse on backfilled scans (the result dict doesn't carry them yet) — that's
  future engagement-side capture, not a store gap.
- **C2 — Read + write API. ✅ DONE.** `server.py` rewritten DB-backed over the DAL: read
  endpoints (scans, overview+engines, filtered/sorted/paginated findings, finding detail w/
  nested exchanges, frontier, probes, events, evidence, **raw** grid), write-back
  (triage/note, analyst columns only), and `/api/report/{id}` rebuilt from the store via
  `store.reconstruct_result`. `raw` = `store.raw_records` UNION (finding/url/probe/exchange/
  event) with per-column + global-q filters. `d4st serve` now takes `--db`. Verified via
  TestClient + live uvicorn boot against the backfill (dvwa raw = 259 records; write-back
  persists; report has no grade). Tests: `tests/test_server.py` (6). Full suite 119 pass.
- **C3 — SPA findings + overview. ✅ DONE.** `webui.py` rewritten as a dependency-free
  vanilla-JS SPA against the C2 API: dynamic sidebar (scan list, top-severity dot), header
  (severity donut computed in JS, coverage sub, session signal), stat strip (drill-in to
  filtered findings), and the Findings table (severity pills, live search, sortable, row-
  expand → reasoning + payload + request/response proof + remediation).
- **C4 — Observability tabs. ✅ DONE.** Attack Surface, Engines, Timeline, Evidence, and
  **Raw Data** (fetches `/raw`; generic per-column filter row — dropdowns auto-populated from
  distinct values + text inputs — global search, sortable, clear-filters).
- **C5 — Write-back. ✅ DONE.** Triage buttons (confirm/false-positive/accept) + analyst note
  field wired to the POST endpoints; row status badge updates; carry-forward across re-ingest
  (C1). Browser-verified: triage + note persist to the DB on re-read.
- **C6 — Live scans. ✅ DONE.** `/api/scans/{id}/live` streams the `D4ST_PROGRESS_FILE`
  checkpoint (else stored terminal status); SPA shows a live bar + polls every 2.5s while a
  scan is in-progress, re-selecting the scan on completion. Test covers both paths.
- **C7 — Polish. ✅ CORE DONE.** Empty states (no scans / no findings match / old-scan empty
  timeline), loading spinners, success/error toasts, 15s sidebar auto-refresh (paused while a
  detail row is open). Deferred as minor: keyboard nav, column prefs, URL deep-links.

**Browser-verified (Chrome, real DB):** all 7 tabs render correct data (dvwa raw=259,
vampi=57, per-kind filter counts exact); findings filter/search/expand; triage + note
round-trip to the DB; scan-switching; zero console errors; no "grade" in the DOM. Two
findings-size caps (`le`) were raised after the browser surfaced 422s at size=2000/5000.
Full suite **120 pass**.

## Explicitly deferred — separate track

- **Report heavy work.** The standalone `d4st report` HTML is its own ongoing workstream
  (owner: "continue heavy work on the report later"). Grade is already stripped there; further
  report improvements are tracked separately from the console build.
- **ASM-NG wire-in.** Optional `POST findings to ASM-NG` export stays schema-compatible; not
  part of the console MVP.
- **Auth on the console.** Off by default; add when a networked deployment needs it.
