# d4st

Standalone open-source DAST (dynamic application security testing) appliance for recurring,
unattended, authenticated web-app scanning. Chains best-in-class open-source scanners behind
a single captured session, deduplicates and verifies findings, and reports coverage on par
with commercial DAST at open-source cost.

Designed as an ASM-NG satellite: it is its own standalone program (no SpiderFoot / ASM-NG
runtime dependency) and can optionally POST findings via its REST API for a unified view.

## Purpose

Replaces recurring Burp Suite Enterprise authenticated scanning with a self-hosted pipeline
that runs inside the client network. See `docs/` and the design plan for the full rationale
and the DVWA-vs-Burp-Pro coverage benchmark.

## Architecture

```
  auth (Playwright storageState + TOTP)  --> one captured session
                                             |
  ORCHESTRATOR (thin, YAML-declared workflow)
    recon/discovery -> crawl -> scan/detect -> TLS
    + shared URL/param FRONTIER with convergence loop
                                             |
  normalize -> verify (deterministic replay, FP-hold) -> own findings store + UI
                                             |
                          (optional) POST to ASM-NG REST API
```

- **Standalone clean fork.** Valuable ASM-NG subsystems (verify layer, findings model,
  normalization/taxonomy, React panes) are forked in and re-homed on this tool's own
  Postgres + REST + React. Each forked file carries an `UPSTREAM:` header. The findings
  schema is kept ASM-NG-compatible so the optional wire-in stays trivial.
- **Every tool is an adapter** implementing `run(target, session) -> native_json`. Workflows
  are declared in YAML (`d4st/workflows/*.yaml`).
- **Shared frontier**: every discovery tool feeds a deduplicated URL/param frontier that the
  scanners re-consume (capped convergence loop; coverage caps are logged, never silently
  truncated).

## Status

Early build. Phase 0 (scaffold + orchestrator skeleton) in place. See the design plan for
the full phase sequence (auth module -> core subset -> DVWA/WAVSEP pilot -> full roster ->
own backend/UI -> FHC MFA pilot).

## Quick start (dev)

```bash
pip install -e ".[dev]"
d4st version
d4st launch --workflow core --target https://dvwa.local --dry-run
```

## License

MIT
