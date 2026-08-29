"""dast-ng observability store — SQLite spine for the web console.

The CLI stays file-based; this module ingests an engagement result dict into a small,
indexed SQLite database that the console (server.py) reads. Nothing here changes how a
scan runs. See docs/console-build-plan.md.

Design notes:
  * Pure stdlib sqlite3, WAL mode (safe concurrent read while a live scan writes).
  * Severity/CWE/OWASP/title/fix are NOT stored on findings by the pipeline; they are a
    render-time join on `category` via report.VULN_META. We denormalise that join in at
    ingest so the UI never computes it.
  * There is NO grade/posture column, by decision — this is an observability tool, not a
    scorecard.
  * ingest() is idempotent: re-ingesting a scan_id replaces its rows (delete+reinsert) and
    carries analyst triage_status / analyst_note forward by dedup_key.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from .report import SEV_ORDER, _meta_for

DEFAULT_DB = os.path.expanduser("~/.dastng/dastng.db")


def db_path(path: str | None = None) -> str:
    p = path or os.environ.get("DASTNG_DB") or DEFAULT_DB
    Path(p).expanduser().parent.mkdir(parents=True, exist_ok=True)
    return str(Path(p).expanduser())


def connect(path: str | None = None) -> sqlite3.Connection:
    con = sqlite3.connect(db_path(path), timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA synchronous=NORMAL")
    return con


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  target TEXT, profile TEXT, created_at INTEGER, status TEXT, app_type TEXT,
  urls_count INTEGER, targets_count INTEGER, exchanges_count INTEGER, n_findings INTEGER,
  sev_critical INTEGER, sev_high INTEGER, sev_medium INTEGER, sev_low INTEGER, sev_info INTEGER,
  session_keeper INTEGER, reauths INTEGER, authed_at_end INTEGER, halted INTEGER, stage INTEGER,
  sqlmap_level INTEGER, policy_json TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
  dedup_key TEXT, tool TEXT, category TEXT, url TEXT, url_path TEXT, param TEXT, method TEXT,
  evidence TEXT, payload TEXT, detection TEXT, confidence TEXT,
  verified INTEGER, verify_note TEXT, repro TEXT, raw_output TEXT,
  severity TEXT, cwe TEXT, owasp TEXT, vtitle TEXT, vdesc TEXT, vfix TEXT,
  triage_status TEXT DEFAULT 'open', analyst_note TEXT, updated_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_find_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS ix_find_sev  ON findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS ix_find_cat  ON findings(scan_id, category);
CREATE INDEX IF NOT EXISTS ix_find_tool ON findings(scan_id, tool);
CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY, finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
  scan_id TEXT, seq INTEGER, label TEXT,
  req_method TEXT, req_url TEXT, req_headers TEXT, req_body TEXT,
  resp_status INTEGER, resp_headers TEXT, resp_elapsed_ms INTEGER, resp_size INTEGER,
  resp_body TEXT, truncated INTEGER
);
CREATE INDEX IF NOT EXISTS ix_ev_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS ix_ev_scan ON evidence(scan_id);
CREATE TABLE IF NOT EXISTS frontier_urls (
  id INTEGER PRIMARY KEY, scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
  url TEXT, discovered_by TEXT, param_count INTEGER, is_target INTEGER, hit_by TEXT
);
CREATE INDEX IF NOT EXISTS ix_fr_scan ON frontier_urls(scan_id);
CREATE TABLE IF NOT EXISTS probes (
  id INTEGER PRIMARY KEY, scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
  engine TEXT, ran INTEGER, expected INTEGER, note TEXT, findings_count INTEGER,
  command TEXT, raw_tail TEXT
);
CREATE INDEX IF NOT EXISTS ix_pr_scan ON probes(scan_id);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
  seq INTEGER, ts INTEGER, kind TEXT, stage TEXT, message TEXT, data_json TEXT
);
CREATE INDEX IF NOT EXISTS ix_ev2_scan ON events(scan_id);
"""


def init_schema(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    con.commit()


# ---- helpers ----------------------------------------------------------------

def _path_of(url: str) -> str:
    try:
        return urlsplit(url or "").path or "/"
    except Exception:  # noqa: BLE001
        return url or ""


def _dedup_key(cat: str, url: str, param) -> str:
    return f"{cat}|{_path_of(url)}|{param or ''}"


def _as_int_bool(v) -> int | None:
    if v is None:
        return None
    return 1 if v else 0


def _find_count_from_note(note: str) -> int | None:
    m = re.search(r"(\d+)\s*finding", str(note or ""))
    return int(m.group(1)) if m else None


def _fingerprint_app_type(chain: list) -> str:
    for c in chain or []:
        if c.get("engine") == "fingerprint":
            return str(c.get("note") or "")
    return ""


# ---- ingest -----------------------------------------------------------------

def ingest(result: dict, scan_id: str, con: sqlite3.Connection | None = None,
           created_at: int | None = None, status: str = "complete") -> dict:
    """Load one engagement result dict into the store under `scan_id`.
    Idempotent: replaces any existing rows for this scan_id and carries analyst
    triage/notes forward by dedup_key. Returns a small summary dict.
    """
    own = con is None
    con = con or connect()
    init_schema(con)
    created_at = created_at or int(time.time())

    findings = result.get("findings", []) or []

    # carry-forward: snapshot existing analyst state for this scan before wiping it
    carry: dict[str, tuple] = {}
    for r in con.execute(
            "SELECT dedup_key, triage_status, analyst_note FROM findings WHERE scan_id=?",
            (scan_id,)):
        carry[r["dedup_key"]] = (r["triage_status"], r["analyst_note"])

    # wipe prior rows for this scan (CASCADE clears evidence/frontier/probes/events)
    con.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
    con.execute("DELETE FROM frontier_urls WHERE scan_id=?", (scan_id,))
    con.execute("DELETE FROM probes WHERE scan_id=?", (scan_id,))
    con.execute("DELETE FROM events WHERE scan_id=?", (scan_id,))
    con.execute("DELETE FROM scans WHERE id=?", (scan_id,))

    # severity mix + enrichment
    sev = Counter()
    exchanges_total = 0
    # map of finding URL -> "category · tool" for frontier hit_by derivation. Keyed by the
    # FULL url (not just path): path-only matching over-claims because many passive findings
    # share path '/'. Full-url is conservative — it never falsely claims a url was hit.
    hit_by: dict[str, str] = {}

    for f in findings:
        cat = f.get("category", "other")
        meta = _meta_for(cat)
        sev[meta["severity"]] += 1
        exchanges_total += len(f.get("evidence_log") or [])
        hit_by.setdefault(f.get("url", ""), f"{cat} · {f.get('tool', '?')}")

    session = result.get("session") or {}
    health = result.get("health") or {}
    policy = result.get("policy") or {}
    chain = result.get("chain") or []

    con.execute(
        """INSERT INTO scans (id,target,profile,created_at,status,app_type,urls_count,
             targets_count,exchanges_count,n_findings,sev_critical,sev_high,sev_medium,
             sev_low,sev_info,session_keeper,reauths,authed_at_end,halted,stage,sqlmap_level,
             policy_json)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (scan_id, result.get("target") or (findings[0]["url"] if findings else ""),
         policy.get("name"), created_at, status, _fingerprint_app_type(chain),
         len(result.get("urls") or []), result.get("targets") or 0, exchanges_total,
         len(findings), sev.get("critical", 0), sev.get("high", 0), sev.get("medium", 0),
         sev.get("low", 0), sev.get("info", 0),
         _as_int_bool(session.get("keeper")), session.get("reauths") or 0,
         _as_int_bool(session.get("authed_at_end")), _as_int_bool(health.get("halted")),
         health.get("stage"), health.get("sqlmap_level_used"), json.dumps(policy)))

    # findings + evidence
    for f in findings:
        cat = f.get("category", "other")
        meta = _meta_for(cat)
        url = f.get("url", "")
        dk = _dedup_key(cat, url, f.get("param"))
        prior = carry.get(dk)
        triage = prior[0] if prior else "open"
        note = prior[1] if prior else None
        cur = con.execute(
            """INSERT INTO findings (scan_id,dedup_key,tool,category,url,url_path,param,method,
                 evidence,payload,detection,confidence,verified,verify_note,repro,raw_output,
                 severity,cwe,owasp,vtitle,vdesc,vfix,triage_status,analyst_note,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, dk, f.get("tool"), cat, url, _path_of(url), f.get("param"),
             f.get("method", "GET"), f.get("evidence", ""), f.get("payload", ""),
             f.get("detection", ""), f.get("confidence", ""), _as_int_bool(f.get("verified")),
             f.get("verify_note", ""), f.get("repro", ""), f.get("raw_output", ""),
             meta["severity"], meta["cwe"], meta["owasp"], meta["title"], meta.get("desc", ""),
             meta["fix"], triage, note, created_at))
        fid = cur.lastrowid
        for seq, ex in enumerate(f.get("evidence_log") or []):
            req = ex.get("request") or {}
            resp = ex.get("response") or {}
            con.execute(
                """INSERT INTO evidence (finding_id,scan_id,seq,label,req_method,req_url,
                     req_headers,req_body,resp_status,resp_headers,resp_elapsed_ms,resp_size,
                     resp_body,truncated)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (fid, scan_id, seq, ex.get("label", ""), req.get("method"), req.get("url"),
                 json.dumps(req.get("headers")), req.get("body"), resp.get("status"),
                 json.dumps(resp.get("headers")), resp.get("elapsed_ms"), resp.get("size"),
                 resp.get("body"), _as_int_bool(resp.get("truncated"))))

    # frontier — result['urls'] is a flat list of URL strings; derive hit_by from findings.
    # discovered_by / is_target aren't in the result dict today (future engagement enrichment).
    for u in result.get("urls") or []:
        q = urlsplit(u).query
        pc = len([p for p in q.split("&") if p]) if q else 0
        con.execute(
            "INSERT INTO frontier_urls (scan_id,url,discovered_by,param_count,is_target,hit_by)"
            " VALUES (?,?,?,?,?,?)",
            (scan_id, u, None, pc, None, hit_by.get(u)))

    # probes — the engine chain
    for c in chain:
        con.execute(
            "INSERT INTO probes (scan_id,engine,ran,expected,note,findings_count,command,raw_tail)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, c.get("engine"), _as_int_bool(c.get("ran")), _as_int_bool(c.get("expected")),
             c.get("note"), _find_count_from_note(c.get("note")), c.get("command"), c.get("raw_tail")))

    # events — health.events (shape may be dict or str); sparse for old scans, that's honest
    for seq, ev in enumerate(health.get("events") or []):
        if isinstance(ev, dict):
            con.execute(
                "INSERT INTO events (scan_id,seq,ts,kind,stage,message,data_json)"
                " VALUES (?,?,?,?,?,?,?)",
                (scan_id, seq, ev.get("ts"), ev.get("kind"), ev.get("stage"),
                 ev.get("message") or ev.get("msg"), json.dumps(ev)))
        else:
            con.execute(
                "INSERT INTO events (scan_id,seq,ts,kind,stage,message,data_json)"
                " VALUES (?,?,?,?,?,?,?)",
                (scan_id, seq, None, "note", None, str(ev), None))

    con.commit()
    summary = {"scan_id": scan_id, "findings": len(findings), "exchanges": exchanges_total,
               "urls": len(result.get("urls") or []), "engines": len(chain),
               "severities": {s: sev.get(s, 0) for s in SEV_ORDER},
               "carried_forward": sum(1 for k in carry if k)}
    if own:
        con.close()
    return summary


# ---- read helpers (used by server.py in C2; handy for verifying the backfill) ----

def list_scans(con: sqlite3.Connection) -> list[dict]:
    rows = con.execute(
        "SELECT id,target,profile,created_at,status,n_findings,sev_critical,sev_high,"
        "sev_medium,sev_low,sev_info,urls_count,targets_count FROM scans "
        "ORDER BY created_at DESC")
    return [dict(r) for r in rows]


def scan_overview(con: sqlite3.Connection, scan_id: str) -> dict | None:
    r = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return dict(r) if r else None


def query_findings(con: sqlite3.Connection, scan_id: str, *, severity: str | None = None,
                   category: str | None = None, tool: str | None = None,
                   verified: int | None = None, triage: str | None = None,
                   q: str | None = None, sort: str = "severity", direction: str = "asc",
                   limit: int = 100, offset: int = 0) -> list[dict]:
    where = ["scan_id=?"]
    args: list = [scan_id]
    if severity:
        where.append("severity=?"); args.append(severity)
    if category:
        where.append("category=?"); args.append(category)
    if tool:
        where.append("tool=?"); args.append(tool)
    if verified is not None:
        where.append("verified=?"); args.append(verified)
    if triage:
        where.append("triage_status=?"); args.append(triage)
    if q:
        where.append("(url LIKE ? OR param LIKE ? OR category LIKE ? OR vtitle LIKE ?)")
        args += [f"%{q}%"] * 4
    # severity sorts by canonical rank, not alphabetical
    if sort == "severity":
        order = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                 "WHEN 'low' THEN 3 ELSE 4 END")
    else:
        order = sort if sort in {"category", "tool", "url", "param", "verified",
                                 "confidence", "triage_status"} else "id"
    order += " DESC" if str(direction).lower() == "desc" else " ASC"
    sql = (f"SELECT id,tool,category,url,param,method,severity,cwe,owasp,vtitle,verified,"
           f"confidence,triage_status FROM findings WHERE {' AND '.join(where)} "
           f"ORDER BY {order} LIMIT ? OFFSET ?")
    args += [limit, offset]
    return [dict(r) for r in con.execute(sql, args)]


def _jload(s):
    try:
        return json.loads(s) if s else None
    except Exception:  # noqa: BLE001
        return s


def _exchange_from_row(e) -> dict:
    """Reassemble a stored evidence row into the pipeline's nested exchange shape
    (what report._render_exchange and the SPA proof() renderer both consume)."""
    return {
        "label": e["label"],
        "request": {"method": e["req_method"], "url": e["req_url"],
                    "headers": _jload(e["req_headers"]), "body": e["req_body"]},
        "response": {"status": e["resp_status"], "headers": _jload(e["resp_headers"]),
                     "elapsed_ms": e["resp_elapsed_ms"], "size": e["resp_size"],
                     "body": e["resp_body"],
                     "truncated": None if e["truncated"] is None else bool(e["truncated"])},
    }


def finding_detail(con: sqlite3.Connection, fid: int) -> dict | None:
    r = con.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["evidence_log"] = [_exchange_from_row(e) for e in con.execute(
        "SELECT * FROM evidence WHERE finding_id=? ORDER BY seq", (fid,))]
    return d


def scan_evidence(con: sqlite3.Connection, scan_id: str, q: str | None = None,
                  limit: int = 500, offset: int = 0) -> list[dict]:
    """Every captured request/response exchange for a scan (global evidence browser)."""
    where = ["e.scan_id=?"]
    args: list = [scan_id]
    if q:
        where.append("(e.req_url LIKE ? OR e.label LIKE ?)")
        args += [f"%{q}%", f"%{q}%"]
    sql = (f"SELECT e.*, f.category, f.tool FROM evidence e JOIN findings f ON e.finding_id=f.id "
           f"WHERE {' AND '.join(where)} ORDER BY e.id LIMIT ? OFFSET ?")
    args += [limit, offset]
    out = []
    for r in con.execute(sql, args):
        ex = _exchange_from_row(r)
        ex.update({"finding_id": r["finding_id"], "category": r["category"], "tool": r["tool"]})
        out.append(ex)
    return out


def raw_records(con: sqlite3.Connection, scan_id: str, *, filters: dict | None = None,
                q: str | None = None, sort: str | None = None, direction: str = "asc",
                limit: int = 500, offset: int = 0) -> list[dict]:
    """The RAW DATA grid: UNION of every collected record projected to one column set.
    kinds: finding | url | probe | exchange | event."""
    cols = ["kind", "source", "type", "url", "param", "method", "severity", "status", "detail"]
    union = """
      SELECT 'finding' kind, tool source, category type, url, param, method, severity,
             CASE WHEN verified=1 THEN 'verified' WHEN verified=0 THEN 'unconfirmed'
                  ELSE triage_status END status, COALESCE(vtitle,evidence) detail
        FROM findings WHERE scan_id=:sid
      UNION ALL
      SELECT 'url', discovered_by, 'frontier', url, CAST(param_count AS TEXT), '', '',
             CASE WHEN is_target=1 THEN 'target' ELSE '' END, COALESCE(hit_by,'') FROM frontier_urls WHERE scan_id=:sid
      UNION ALL
      SELECT 'probe', engine, 'engine', '', '', '', '',
             CASE WHEN ran=1 THEN 'ran' ELSE 'skipped' END, note FROM probes WHERE scan_id=:sid
      UNION ALL
      SELECT 'exchange', f.tool, 'http', e.req_url, f.param, e.req_method, '',
             CAST(e.resp_status AS TEXT), e.label
        FROM evidence e JOIN findings f ON e.finding_id=f.id WHERE e.scan_id=:sid
      UNION ALL
      SELECT 'event', '', kind, '', '', '', '', COALESCE(stage,''), message FROM events WHERE scan_id=:sid
    """
    where = []
    params: dict = {"sid": scan_id}
    for i, (k, v) in enumerate((filters or {}).items()):
        if v in (None, ""):
            continue
        if k not in cols:
            continue
        # dropdown columns match exactly; freeform match by contains
        if k in {"kind", "source", "method", "severity", "status"}:
            where.append(f"{k}=:f{i}"); params[f"f{i}"] = v
        else:
            where.append(f"{k} LIKE :f{i}"); params[f"f{i}"] = f"%{v}%"
    if q:
        where.append("(" + " OR ".join(f"{c} LIKE :q" for c in cols) + ")")
        params["q"] = f"%{q}%"
    order = (sort if sort in cols else "kind")
    order += " DESC" if str(direction).lower() == "desc" else " ASC"
    sql = f"SELECT * FROM ({union}) WHERE {' AND '.join(where) if where else '1=1'} ORDER BY {order} LIMIT :lim OFFSET :off"
    params.update(lim=limit, off=offset)
    return [dict(r) for r in con.execute(sql, params)]


def reconstruct_result(con: sqlite3.Connection, scan_id: str) -> dict | None:
    """Rebuild the engagement result dict from the store (for the HTML report)."""
    s = scan_overview(con, scan_id)
    if not s:
        return None
    findings = []
    for f in con.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)):
        el = [_exchange_from_row(e) for e in con.execute(
            "SELECT * FROM evidence WHERE finding_id=? ORDER BY seq", (f["id"],))]
        findings.append({
            "tool": f["tool"], "category": f["category"], "url": f["url"], "param": f["param"],
            "method": f["method"], "evidence": f["evidence"],
            "verified": None if f["verified"] is None else bool(f["verified"]),
            "verify_note": f["verify_note"], "payload": f["payload"], "detection": f["detection"],
            "confidence": f["confidence"], "raw_output": f["raw_output"], "repro": f["repro"],
            "evidence_log": el})
    urls = [r["url"] for r in con.execute(
        "SELECT url FROM frontier_urls WHERE scan_id=?", (scan_id,))]
    chain = [{"engine": p["engine"], "ran": bool(p["ran"]), "expected": bool(p["expected"]),
              "note": p["note"]} for p in probes(con, scan_id)]
    return {
        "target": s["target"], "urls": urls, "targets": s["targets_count"], "findings": findings,
        "policy": _jload(s["policy_json"]) or {},
        "session": {"keeper": bool(s["session_keeper"]), "reauths": s["reauths"],
                    "authed_at_end": bool(s["authed_at_end"])},
        "chain": chain, "warnings": [],
        "health": {"stage": s["stage"], "halted": bool(s["halted"]),
                   "sqlmap_level_used": s["sqlmap_level"]}}


def frontier(con: sqlite3.Connection, scan_id: str) -> list[dict]:
    return [dict(r) for r in con.execute(
        "SELECT url,discovered_by,param_count,is_target,hit_by FROM frontier_urls "
        "WHERE scan_id=? ORDER BY (hit_by IS NOT NULL) DESC, url", (scan_id,))]


def probes(con: sqlite3.Connection, scan_id: str) -> list[dict]:
    return [dict(r) for r in con.execute(
        "SELECT engine,ran,expected,note,findings_count,command,raw_tail FROM probes "
        "WHERE scan_id=? ORDER BY id", (scan_id,))]


def events(con: sqlite3.Connection, scan_id: str) -> list[dict]:
    return [dict(r) for r in con.execute(
        "SELECT seq,ts,kind,stage,message,data_json FROM events WHERE scan_id=? ORDER BY seq",
        (scan_id,))]


def set_triage(con: sqlite3.Connection, fid: int, status: str) -> None:
    con.execute("UPDATE findings SET triage_status=?, updated_at=? WHERE id=?",
                (status, int(time.time()), fid))
    con.commit()


def set_note(con: sqlite3.Connection, fid: int, note: str) -> None:
    con.execute("UPDATE findings SET analyst_note=?, updated_at=? WHERE id=?",
                (note, int(time.time()), fid))
    con.commit()
