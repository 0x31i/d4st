# DVWA pilot runbook (Phase 3)

Goal: run the d4st core subset and Burp Suite Pro against the same DVWA instance, then
score both against the DVWA oracle and produce the category x tool coverage matrix.

Prereqs (on the pilot machine):
- DVWA reachable on the LAN (power it on).
- Tools installed and on PATH: `katana`, `nuclei`, `sqlmap`, `dalfox`, `commix`,
  `zap-full-scan.py` (ZAP), and `playwright` browsers (`python -m playwright install chromium`).
- Burp Suite Pro (for the reference scan + XML export).

## 1. Capture the DVWA session (once)

```bash
. .venv/bin/activate
d4st auth capture -p dvwa -b http://<dvwa-host> -o sessions/dvwa.json --security low
d4st auth check   -s sessions/dvwa.json -p dvwa -b http://<dvwa-host>   # expect VALID
```

## 2. Run the pipeline (authorized active scan)

Active scanning is gated: `--allow-active` is the per-target authorization. DVWA is the
owner's deliberately-vulnerable box, so this is authorized.

```bash
d4st launch -w core -t http://<dvwa-host>/ -s sessions/dvwa.json --allow-active --json > runs/dvwa.json
```

Save each tool's native output into a results dir (nuclei.jsonl, dalfox.json, zap.json,
sqlmap.txt, commix.txt). Until the run-artifact writer lands (Phase 6), capture native
outputs by running the tools with the session cookie, or lift them from the run.

## 3. Run Burp Pro (reference)

Scan the same DVWA scope authenticated, then export: Target -> right-click -> Report issues
-> XML -> `burp.xml`. Control for crawling by giving Burp the same URL scope as katana.

## 4. Score

```bash
d4st score -O dvwa -r results/ --burp burp.xml -o report.json
```

This prints the category x tool recall matrix with the pipeline-union column, the Burp
reference column, and the delta (pipeline - burp). `report.json` holds the full detail.

## Levels

- `low`  : max-recall measurement.
- `high` : exercises the per-request `user_token` anti-CSRF path (auth-module stress).
- `impossible` : false-positive control (should yield ~no findings).

## Notes

- Recall is the headline metric here; precision on DVWA is noisy (DVWA has real issues beyond
  the oracle). WAVSEP (Phase 4) is the clean precision/specificity benchmark.
- Edit `d4st/scoring/oracles/dvwa.yaml` if your DVWA build's endpoints/params differ.
