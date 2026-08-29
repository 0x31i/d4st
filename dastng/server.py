"""dast-ng web console — DB-backed FastAPI API over the SQLite observability store.

    dastng serve [--db ~/.dastng/dastng.db] [--port 8810]

The store is populated by `dast-ng ingest` (backfill) and auto-ingested at scan-end. This
module only reads/writes the analyst columns; scan data is immutable. There is no grade — the
console is an observability tool, not a scorecard. See docs/console-build-plan.md.

Read:
  GET /api/scans                         list scans (sidebar)
  GET /api/scans/{id}                    overview (coverage, session health, policy, engines)
  GET /api/scans/{id}/findings           filtered/sorted/paginated findings
  GET /api/findings/{fid}                one finding + its request/response exchanges
  GET /api/scans/{id}/frontier           attack-surface (crawl reach)
  GET /api/scans/{id}/probes             engine chain
  GET /api/scans/{id}/events             timeline
  GET /api/scans/{id}/evidence           global exchange browser
  GET /api/scans/{id}/raw                RAW DATA grid (union of every record, per-col filters)
  GET /api/report/{id}                   self-contained HTML report (rebuilt from the store)
Write-back (analyst columns only):
  POST /api/findings/{fid}/triage        {status}
  POST /api/findings/{fid}/note          {note}
"""
from __future__ import annotations

from . import store
from .report import build_report
from .webui import INDEX_HTML as _INDEX_HTML

TRIAGE_STATES = {"open", "confirmed", "false_positive", "accepted"}


def create_app(db_path: str | None = None):
    from fastapi import Body, FastAPI, HTTPException, Query
    from fastapi.responses import HTMLResponse, JSONResponse

    app = FastAPI(title="dast-ng console", docs_url=None, redoc_url=None)
    dbp = store.db_path(db_path)

    def con():
        return store.connect(dbp)

    def _require_scan(c, scan_id: str) -> dict:
        s = store.scan_overview(c, scan_id)
        if not s:
            raise HTTPException(404, "scan not found")
        return s

    @app.get("/", response_class=HTMLResponse)
    def index():
        return _INDEX_HTML

    @app.get("/api/scans")
    def scans():
        with con() as c:
            return JSONResponse(store.list_scans(c))

    @app.get("/api/scans/{scan_id}")
    def scan_overview(scan_id: str):
        with con() as c:
            s = _require_scan(c, scan_id)
            s["engines"] = store.probes(c, scan_id)
            return JSONResponse(s)

    @app.get("/api/scans/{scan_id}/findings")
    def findings(scan_id: str, severity: str = Query(None), category: str = Query(None),
                 tool: str = Query(None), verified: int = Query(None), triage: str = Query(None),
                 q: str = Query(None), sort: str = Query("severity"), dir: str = Query("asc"),
                 page: int = Query(0, ge=0), size: int = Query(100, ge=1, le=5000)):
        with con() as c:
            _require_scan(c, scan_id)
            rows = store.query_findings(c, scan_id, severity=severity, category=category,
                                        tool=tool, verified=verified, triage=triage, q=q,
                                        sort=sort, direction=dir, limit=size, offset=page * size)
            return JSONResponse(rows)

    @app.get("/api/findings/{fid}")
    def finding(fid: int):
        with con() as c:
            d = store.finding_detail(c, fid)
            if not d:
                raise HTTPException(404, "finding not found")
            return JSONResponse(d)

    @app.get("/api/scans/{scan_id}/frontier")
    def frontier(scan_id: str):
        with con() as c:
            _require_scan(c, scan_id)
            return JSONResponse(store.frontier(c, scan_id))

    @app.get("/api/scans/{scan_id}/probes")
    def probes(scan_id: str):
        with con() as c:
            _require_scan(c, scan_id)
            return JSONResponse(store.probes(c, scan_id))

    @app.get("/api/scans/{scan_id}/events")
    def events(scan_id: str):
        with con() as c:
            _require_scan(c, scan_id)
            return JSONResponse(store.events(c, scan_id))

    @app.get("/api/scans/{scan_id}/evidence")
    def evidence(scan_id: str, q: str = Query(None), page: int = Query(0, ge=0),
                 size: int = Query(500, ge=1, le=2000)):
        with con() as c:
            _require_scan(c, scan_id)
            return JSONResponse(store.scan_evidence(c, scan_id, q=q, limit=size, offset=page * size))

    @app.get("/api/scans/{scan_id}/raw")
    def raw(scan_id: str, kind: str = Query(None), source: str = Query(None),
            type: str = Query(None), url: str = Query(None), param: str = Query(None),
            method: str = Query(None), severity: str = Query(None), status: str = Query(None),
            detail: str = Query(None), q: str = Query(None), sort: str = Query(None),
            dir: str = Query("asc"), page: int = Query(0, ge=0), size: int = Query(500, ge=1, le=20000)):
        filters = {"kind": kind, "source": source, "type": type, "url": url, "param": param,
                   "method": method, "severity": severity, "status": status, "detail": detail}
        with con() as c:
            _require_scan(c, scan_id)
            return JSONResponse(store.raw_records(c, scan_id, filters=filters, q=q, sort=sort,
                                                  direction=dir, limit=size, offset=page * size))

    @app.post("/api/findings/{fid}/triage")
    def set_triage(fid: int, body: dict = Body(...)):
        status = (body or {}).get("status")
        if status not in TRIAGE_STATES:
            raise HTTPException(400, f"status must be one of {sorted(TRIAGE_STATES)}")
        with con() as c:
            if not store.finding_detail(c, fid):
                raise HTTPException(404, "finding not found")
            store.set_triage(c, fid, status)
            return JSONResponse({"ok": True, "id": fid, "triage_status": status})

    @app.post("/api/findings/{fid}/note")
    def set_note(fid: int, body: dict = Body(...)):
        with con() as c:
            if not store.finding_detail(c, fid):
                raise HTTPException(404, "finding not found")
            store.set_note(c, fid, (body or {}).get("note", ""))
            return JSONResponse({"ok": True, "id": fid})

    @app.get("/api/scans/{scan_id}/live")
    def live(scan_id: str):
        """Live-scan feed: if an in-progress checkpoint file exists (DASTNG_PROGRESS_FILE,
        written by run_engagement after every stage), return it so the console can stream
        stages/findings/timeline in real time. Otherwise report the stored terminal status."""
        import json as _j
        import os as _os
        pf = _os.environ.get("DASTNG_PROGRESS_FILE")
        if pf and _os.path.exists(pf):
            try:
                return JSONResponse(_j.loads(open(pf, encoding="utf-8").read()))
            except Exception:  # noqa: BLE001
                pass
        with con() as c:
            s = store.scan_overview(c, scan_id)
            return JSONResponse({"status": s["status"] if s else "unknown", "live": False})

    @app.get("/api/report/{scan_id}", response_class=HTMLResponse)
    def report(scan_id: str):
        with con() as c:
            result = store.reconstruct_result(c, scan_id)
            if not result:
                raise HTTPException(404, "scan not found")
            return build_report(result, target=result.get("target", ""))

    return app


def run_server(host: str = "127.0.0.1", port: int = 8810, db_path: str | None = None):
    import uvicorn
    dbp = store.db_path(db_path)
    print(f"dast-ng console  ->  http://{host}:{port}   (db: {dbp})")
    uvicorn.run(create_app(dbp), host=host, port=port, log_level="warning")
