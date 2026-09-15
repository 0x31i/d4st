<p align="center">
  <img src="assets/d4st-logo-wide.png" alt="d4st" width="820">
</p>

<h3 align="center">Standalone open-source DAST appliance</h3>

<p align="center">
  Recurring, unattended, authenticated web-app scanning. A stack of open-source scanners runs
  behind one captured session, findings get verified before you see them, and the output is a
  client-grade report.
</p>

<p align="center">
  <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-6E56CF.svg">
  <img alt="Deploy: Docker" src="https://img.shields.io/badge/Deploy-Docker-2496ED?logo=docker&logoColor=white">
  <img alt="Scanners: 25+" src="https://img.shields.io/badge/Scanners-25%2B-8B5CF6">
  <img alt="Auth: Playwright + TOTP" src="https://img.shields.io/badge/Auth-Playwright%20%2B%20TOTP-4C1D95">
  <img alt="CLI-first" src="https://img.shields.io/badge/Interface-CLI--first-1F1147">
</p>

<p align="center">
  <video src="https://github.com/0x31i/d4st/raw/main/assets/d4st-intro.mp4" controls muted width="760"></video>
</p>

---

d4st runs a stack of open-source scanners behind a single captured login session. The tools
share one crawl frontier, their findings are normalized and replayed to drop false positives,
and the result is a client-grade report. Coverage is comparable to commercial DAST at
open-source cost.

It is self-hosted, so it runs inside your own network with no off-VPN reachability problem. It
ships as one Docker image and it is CLI-first, so it automates cleanly. It covers the recurring
automated scan tier of a commercial suite. It does not replace a human doing manual testing.

---

## Why d4st

- **Authenticated by default.** Most scanners see the login page and stop. d4st captures a real
  browser session (Playwright storage state plus TOTP) and keeps it alive for the whole scan. If
  the session dies, the scan halts loudly instead of quietly scanning the login wall and
  reporting nothing wrong.
- **One frontier, every engine.** The crawler, content brute-forcer, JS route extractor,
  historical-URL puller, and hidden-parameter finder all feed one deduplicated URL/param
  frontier. Every scanner works from that same list. When coverage is capped, the cap is logged.
- **Verified findings.** Findings are normalized to a common schema and replayed through a
  deterministic verify pass that holds suspected false positives, so you triage confirmed
  results.
- **Authenticated attack depth, not just scanning.** Behind the login it runs the tests a human
  does by hand: a JWT attack suite (alg:none, signature stripping, `kid`/`jku` injection, weak-
  secret cracking), SignalR/WebSocket broken-auth, CORS exploitability (reflected-origin + creds),
  HTTP verb/method tampering (BFLA), host-header injection, and a two-account horizontal BOLA/IDOR
  matrix — the classes a generic scanner structurally misses.
- **Evidence on every finding.** Each finding carries the full request/response exchange plus a
  copy-paste `curl` repro — Burp-grade proof, guaranteed (a finding never ships without it). A
  final capture pass replays every finding authenticated and follows redirects, so the proof is
  the real 200/HTML response, not an empty 30x. Tool-side placeholder exchanges (e.g. a ZAP
  passive alert with no captured body) are superseded by that real capture, and anything that
  still can't be proven live is downgraded from "verified" rather than shipped with empty proof.
- **Noise control that matches its own claims.** Passive "missing security header" alerts are
  re-checked against the real captured response and dropped when they don't apply (redirect,
  empty, or non-HTML body, or the header is actually present). Single-page apps that serve the
  same shell on every route no longer inflate the count — the identical-body duplicates collapse
  to one finding annotated with the routes it affects.
- **One config per engagement.** `d4st init` records a login once in a browser and writes the
  auth profile + a single `engagement.yaml`; `d4st run engagement.yaml` captures the session,
  exports every tuning knob, and scans. New target to first scan in one flow, no env-var wrangling.
- **Safe on live infra.** The default `safe-deep` policy throttles requests, never mutates data,
  skips destructive or notifying endpoints, and uses non-corrupting injection techniques. It
  still runs the full roster at full depth. Pace and depth are separate settings.
- **Honest engine health.** Every scan reports which engines fired and which did not, so a
  missing tool shows up as an alarm rather than a silent gap.

## Tool roster

Each tool is an adapter (`run() -> native_json`) whose output is normalized and merged. The
current roster:

| Stage | Tools |
|-------|-------|
| **Auth / session** | Playwright (storage state), pyotp (TOTP), session keeper (probe + re-auth) |
| **Recon / fingerprint** | whatweb, katana, gau |
| **Crawl / discovery** | katana, feroxbuster, ffuf, x8 (hidden params), link-harvester |
| **JS / secrets** | jsluice, semgrep, trufflehog, gitleaks, retire.js-lite dependency check |
| **API / GraphQL** | schemathesis, jwt_tool, graphw00f |
| **Active detection** | OWASP ZAP (active), nuclei (`-dast`), sqlmap, ghauri, dalfox, commix, SSTImap, crlfuzz, nosqli, openredirex, dotdotpwn, interactsh (OAST) |
| **Auth / access-control depth** | JWT attack suite (alg:none · sig-strip · kid/jku · weak-secret crack), SignalR/WebSocket broken-auth, CORS exploitability, verb/method tampering (BFLA), host-header injection, two-account BOLA/IDOR matrix, disclosed-secret impact validation |
| **TLS / infra** | testssl.sh, stdlib cert/protocol check, security-header + tech/version-disclosure passive checks |
| **Verify / report** | deterministic replay verifier, full req/resp evidence capture, client-grade HTML/PDF + xlsx/csv report, SQLite observability console with live in-flight scan monitoring |

## Quick start (Docker)

The whole scanner stack runs in one container, so you install none of the tools on the host.

```bash
git clone https://github.com/0x31i/d4st.git && cd d4st
docker compose pull                       # pulls the prebuilt image (ghcr.io/0x31i/d4st:core)
docker compose up -d
docker compose exec d4st d4st selftest    # verify every tool -> parser path is healthy
```

Onboard a new target in one flow — `d4st init` records the login in a browser (once), detects the
session token, and writes both the auth profile and a single `engagement.yaml`:

```bash
d4st init                                 # prompts for client + target, opens a browser to log in
export APP_USERNAME=… APP_PASSWORD=…      # creds referenced by the generated config
d4st run engagement.yaml                  # auto-captures the session, exports every knob, scans
d4st run engagement.yaml --preflight-only # dry readiness check (reachability, bearer, scope) first
```

`engagement.yaml` declares the whole run — target, scope, auth, scan profile, tuning, an optional
second account for the BOLA matrix, and egress — so nothing lives in scattered environment variables.

<details><summary>Manual path (no config file)</summary>

```bash
# capture the login once (headed the first time for SSO / MFA):
docker compose exec d4st d4st auth capture -p <profile> -b https://app.example.com \
  -o sessions/app.json --headed

# blind authenticated engagement (crawl -> discover -> scan -> verify -> report):
docker compose exec d4st d4st engagement -t https://app.example.com \
  -s sessions/app.json --profile engagement -o results/app.json
```
</details>

Watch it live in the console at `http://localhost:8810` — a running scan shows up immediately with a
per-stage progress feed and findings that grow in real time. Then render the client report:

```bash
docker compose exec d4st d4st report app --from-db --client "Example Corp" -o results/app.pdf
```

See [`docs/deploy-windows.md`](docs/deploy-windows.md) for running on a Windows VM via WSL2.

## Commands

| Command | Purpose |
|---------|---------|
| `d4st init` | Guided onboarding: record the login in a browser, generate the auth profile + a ready `engagement.yaml`. |
| `d4st run <engagement.yaml>` | Run a full engagement from one config file (auto-captures session, exports all tuning, scans). `--preflight-only` for a dry readiness check. |
| `d4st init-config` | Write a blank commented `engagement.yaml` template to fill in by hand. |
| `d4st auth init <login-url>` | Record-to-configure: log in once, auto-detect selectors + token, write the auth profile. |
| `d4st auth capture` | Establish and persist a login session from an existing profile (form / SSO / TOTP). |
| `d4st engagement` | Blind authenticated engagement: crawl, discover forms/CSRF, scan, verify, report. |
| `d4st report` | Render a client-grade HTML/PDF report from a result JSON or the store. |
| `d4st serve` | Start the web console (live scan observability and findings). |
| `d4st score` | Score tool output against a known-vuln oracle (recall/precision). |
| `d4st selftest` | Verify every tool-to-parser path against known-vulnerable fixtures. |
| `d4st update` | Fetch the freshest detection content (templates, rules, DBs). |
| `d4st ingest` | Load engagement result JSONs into the observability store. |

## Safety and politeness profiles

Depth and pace are decoupled. Pick a policy with `--profile`, and override the rate separately
with `D4ST_RPS` / `D4ST_CONCURRENCY` without changing detection depth. An adaptive health
monitor lowers the rate on its own (and can abort) if the target starts to struggle.

| Profile | Posture |
|---------|---------|
| `safe-deep` *(default)* | Full roster and full depth, throttled, no data mutation, non-corrupting SQLi, OAST in-network. Safe for live/production infra. |
| `production-safe` | Same, with no form fuzzing and minimal injection depth. The gentlest active profile. |
| `passive-only` | No attack traffic at all. Crawl, TLS, headers, JS, and secrets only. |
| `staging` | Full depth against a disposable target. Faster, allows state-changing fuzzing. |
| `aggressive` | Owned lab, allowlisted. Maximum speed and aggression. |

Extra-gentle deep scan of a fragile live host:

```bash
d4st engagement -t https://app.example.com -s sessions/app.json \
  --profile safe-deep     # deep and throttled
# dial the pace down further, depth unchanged:
D4ST_RPS=1 D4ST_CONCURRENCY=1 d4st engagement ...
```

## Authorization

The engagement command emits active attack traffic (injection payloads, fuzzing, active scan).
Run it only against systems you own or are explicitly authorized to test. Active scanning sits a
tier above passive recon, so scope it per target, get authorization in writing, and prefer
`passive-only` or `production-safe` when in doubt. Blind OAST stays in-network by default, so no
data leaves your environment.

## Architecture

```
  auth (Playwright storage state + TOTP)  ->  one captured session, kept alive
                                              |
  ORCHESTRATOR (thin, YAML-declared workflow)
    recon/fingerprint -> crawl/discovery -> scan/detect -> TLS
    + shared URL/param FRONTIER with a capped convergence loop
                                              |
  normalize -> deterministic verify (FP-hold) -> SQLite store + web console + report
                                              |
                          (optional) POST findings to an external ASM/aggregation platform
```

- **Every tool is an adapter** implementing `run(target, session) -> native_json`. Workflows are
  declared in YAML (`d4st/workflows/*.yaml`).
- **Shared frontier.** Discovery tools feed a deduplicated URL/param frontier the scanners
  re-consume, with iterative deepening, capped rounds, and logged caps.
- **Findings schema** stays compatible with external ASM platforms, so an optional REST wire-in
  is a straight export instead of a translation layer.

## Benchmarking

d4st is regression-tested against the public WAVSEP and DVWA vulnerable-app suites with `d4st
score`, which computes recall and precision against a known-vuln oracle. That way a coverage
change shows up as a number.

## License

MIT. See [LICENSE](LICENSE).
