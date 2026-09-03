# d4st

**A standalone, open-source DAST appliance for recurring, unattended, authenticated web-app
scanning.** d4st chains best-in-class open-source scanners behind a single captured login
session, drives them over a shared crawl frontier, deterministically verifies findings to
suppress false positives, and produces a client-grade report — coverage on par with commercial
DAST, at open-source cost.

It runs self-hosted inside your own network (no off-VPN reachability problem), ships as a
single Docker image, and is CLI-first so it automates cleanly. It replaces the *recurring
automated* scan tier of a commercial DAST suite; it does not replace a human doing manual
testing.

---

## Why d4st

- **Authenticated by default.** Most scanners see the login page and stop. d4st captures a real
  browser session (Playwright storage state + TOTP), keeps it alive across the scan, and fails
  loud if the session dies — so it never silently scans the login wall and reports "all clear."
- **One frontier, every engine.** Every discovery tool (crawler, content brute-force, JS route
  extraction, historical URLs, hidden-parameter finder) feeds a single deduplicated URL/param
  frontier that every scanner re-consumes. Coverage caps are logged, never silently truncated.
- **Verified findings, not raw tool noise.** Findings are normalized to a common schema and run
  through a deterministic replay/verify pass with FP-hold, so what you triage is what's real.
- **Safe on live infra.** A single `safe-deep` policy is throttled, never mutates data, skips
  destructive/notifying endpoints, and uses non-corrupting injection techniques — while still
  running the full tool roster at full depth. Safety and depth are orthogonal.
- **Honest engine health.** Every scan reports which engines fired and which didn't, so a
  missing tool is an explicit alarm, not an invisible gap.

## Tool roster

d4st orchestrates a broad open-source stack; each tool is an adapter (`run() -> native_json`)
whose output is normalized and merged:

| Stage | Tools |
|-------|-------|
| **Auth / session** | Playwright (storage state), pyotp (TOTP), session keeper (probe + re-auth) |
| **Recon / fingerprint** | whatweb, katana, gau |
| **Crawl / discovery** | katana, feroxbuster, ffuf, x8 (hidden params), link-harvester |
| **JS / secrets** | jsluice, semgrep, trufflehog, gitleaks, retire.js-lite dependency check |
| **API / GraphQL** | schemathesis, jwt_tool, graphw00f |
| **Active detection** | OWASP ZAP (active), nuclei (`-dast`), sqlmap, ghauri, dalfox, commix, SSTImap, crlfuzz, nosqli, openredirex, dotdotpwn, interactsh (OAST) |
| **TLS / infra** | testssl.sh |
| **Verify / report** | deterministic replay verifier, client-grade HTML/PDF report, SQLite observability console |

## Quick start (Docker)

The whole scanner stack runs in one container — you don't install any of the tools on the host.

```bash
git clone https://github.com/0x31i/d4st.git && cd d4st
docker compose pull                       # pulls the prebuilt image (ghcr.io/0x31i/d4st:core)
docker compose up -d
docker compose exec d4st d4st selftest    # verify every tool -> parser path is healthy
```

Capture a session, then run an authenticated engagement:

```bash
# capture the login once (headed the first time for SSO / MFA):
docker compose exec d4st d4st auth capture -p <profile> -b https://app.example.com \
  -o sessions/app.json --headed

# blind authenticated engagement (crawl -> discover -> scan -> verify -> report):
docker compose exec d4st d4st engagement -t https://app.example.com \
  -s sessions/app.json --profile safe-deep -o results/app.json
```

Watch it live in the console at `http://localhost:8810`, then render the client report:

```bash
docker compose exec d4st d4st report app --from-db --client "Example Corp" -o results/app.pdf
```

See [`docs/deploy-windows.md`](docs/deploy-windows.md) for running on a Windows VM via WSL2.

## Commands

| Command | Purpose |
|---------|---------|
| `d4st auth capture` | Establish and persist a login session (form / SSO / TOTP). |
| `d4st engagement` | Blind authenticated engagement: crawl → forms/CSRF → scan → verify → report. |
| `d4st report` | Render a client-grade HTML/PDF report from a result JSON or the store. |
| `d4st serve` | Start the web console (live scan observability + findings). |
| `d4st score` | Score tool output against a known-vuln oracle (recall/precision). |
| `d4st selftest` | Verify every tool → parser path against known-vulnerable fixtures. |
| `d4st update` | Fetch the freshest detection content (templates, rules, DBs). |
| `d4st ingest` | Load engagement result JSONs into the observability store. |

## Safety & politeness profiles

Depth and pace are decoupled. Pick a policy with `--profile`; override the rate independently
with `D4ST_RPS` / `D4ST_CONCURRENCY` without changing detection depth. An adaptive health
monitor self-throttles (and can abort) if the target starts to struggle.

| Profile | Posture |
|---------|---------|
| `safe-deep` *(default)* | Full roster + full depth, throttled, no data mutation, non-corrupting SQLi, OAST in-network. Safe for live/production infra. |
| `production-safe` | As above, no form fuzzing, minimal injection depth — the gentlest active profile. |
| `passive-only` | No attack traffic at all: crawl / TLS / headers / JS / secrets only. |
| `staging` | Full depth, disposable target (faster, allows state-changing fuzzing). |
| `aggressive` | Owned lab, allowlisted: maximum speed and aggression. |

Example — extra-gentle deep scan of a fragile live host:

```bash
d4st engagement -t https://app.example.com -s sessions/app.json \
  --profile safe-deep     # deep + throttled
# dial the pace down further, depth unchanged:
D4ST_RPS=1 D4ST_CONCURRENCY=1 d4st engagement ...
```

## Authorization

d4st's engagement emits **active attack traffic** (injection payloads, fuzzing, active scan).
Run it only against systems you own or are explicitly authorized to test. Active scanning is a
higher authorization tier than passive recon — scope it per target, confirm authorization in
writing, and prefer `passive-only` / `production-safe` when in doubt. Blind OAST stays
in-network by default (no data leaves your environment).

## Architecture

```
  auth (Playwright storage state + TOTP)  ─►  one captured session, kept alive
                                              │
  ORCHESTRATOR (thin, YAML-declared workflow)
    recon/fingerprint → crawl/discovery → scan/detect → TLS
    + shared URL/param FRONTIER with a capped convergence loop
                                              │
  normalize → deterministic verify (FP-hold) → SQLite store + web console + report
                                              │
                          (optional) POST findings to an external ASM/aggregation platform
```

- **Every tool is an adapter** implementing `run(target, session) -> native_json`; workflows
  are declared in YAML (`d4st/workflows/*.yaml`).
- **Shared frontier**: discovery tools feed a deduplicated URL/param frontier the scanners
  re-consume (iterative deepening, capped rounds, logged caps).
- **Findings schema** is kept compatible with external ASM platforms so an optional REST
  wire-in stays a trivial export, not a translation layer.

## Benchmarking

d4st is regression-tested against the public **WAVSEP** and **DVWA** vulnerable-app suites via
`d4st score`, which computes recall / precision against a known-vuln oracle so coverage changes
are measured, not assumed.

## License

MIT — see [LICENSE](LICENSE).
