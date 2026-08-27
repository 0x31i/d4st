"""dast-ng web console: a small FastAPI backend + a single-page terminal/hacker-themed dashboard
that lists completed scans and shows each finding with its request/response proof, reasoning, and
remediation. Also serves a downloadable self-contained HTML report per scan.

    dastng serve --scans-dir ~/.dastng/scans
"""
from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

from .report import SEV_ORDER, _grade, _meta_for, build_report

DEFAULT_SCANS_DIR = os.path.expanduser("~/.dastng/scans")


def _scan_dir(scans_dir: str | None) -> Path:
    d = Path(scans_dir or os.environ.get("DASTNG_SCANS_DIR") or DEFAULT_SCANS_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception:  # noqa: BLE001
        return {}


def _summarize(result: dict) -> dict:
    findings = result.get("findings", [])
    sev = Counter(_meta_for(f.get("category", "other"))["severity"] for f in findings)
    grade, posture = _grade(sev)
    tgt = result.get("target") or (findings[0]["url"] if findings else "target")
    return {"findings": len(findings), "grade": grade, "posture": posture,
            "severities": {s: sev.get(s, 0) for s in SEV_ORDER},
            "target": tgt, "urls": len(result.get("urls", [])),
            "targets": result.get("targets", 0)}


def _enrich(f: dict) -> dict:
    m = _meta_for(f.get("category", "other"))
    return {**f, "severity": m["severity"], "vtitle": m["title"], "cwe": m["cwe"],
            "owasp": m["owasp"], "vdesc": m["desc"], "vfix": m["fix"]}


def create_app(scans_dir: str | None = None):
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse

    app = FastAPI(title="dast-ng console", docs_url=None, redoc_url=None)
    base = _scan_dir(scans_dir)

    def _scans() -> list[dict]:
        items = []
        for p in sorted(base.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            r = _load(p)
            if "findings" not in r:
                continue
            s = _summarize(r)
            items.append({"id": p.stem, "mtime": int(p.stat().st_mtime), **s})
        return items

    @app.get("/", response_class=HTMLResponse)
    def index():
        return _INDEX_HTML

    @app.get("/api/scans")
    def scans():
        return JSONResponse(_scans())

    @app.get("/api/scan/{scan_id}")
    def scan(scan_id: str):
        p = base / f"{scan_id}.json"
        if not p.exists():
            raise HTTPException(404, "scan not found")
        r = _load(p)
        return JSONResponse({
            "id": scan_id, "summary": _summarize(r),
            "policy": r.get("policy", {}), "session": r.get("session", {}),
            "zap": r.get("zap", {}),
            "findings": sorted((_enrich(f) for f in r.get("findings", [])),
                               key=lambda f: (SEV_ORDER.index(f["severity"]) if f["severity"] in SEV_ORDER else 9,
                                              f.get("category", ""))),
        })

    @app.get("/api/report/{scan_id}", response_class=HTMLResponse)
    def report(scan_id: str):
        p = base / f"{scan_id}.json"
        if not p.exists():
            raise HTTPException(404, "scan not found")
        r = _load(p)
        return build_report(r, target=r.get("target", ""))

    return app


def run_server(host: str = "127.0.0.1", port: int = 8810, scans_dir: str | None = None):
    import uvicorn
    d = _scan_dir(scans_dir)
    print(f"dast-ng console  ->  http://{host}:{port}   (scans: {d})")
    uvicorn.run(create_app(scans_dir), host=host, port=port, log_level="warning")


# The SPA is defined in a sibling module string to keep this file readable.
from .webui import INDEX_HTML as _INDEX_HTML  # noqa: E402
