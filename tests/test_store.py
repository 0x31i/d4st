"""C1 store: ingest fidelity, enrichment, idempotency, analyst carry-forward."""
import os

from d4st import store


def _result():
    return {
        "target": "http://app.local",
        "urls": ["http://app.local/", "http://app.local/login?next=1", "http://app.local/x?a=1&b=2"],
        "targets": 2,
        "policy": {"name": "safe-deep", "active_scan": True},
        "health": {"stage": 0, "halted": False, "sqlmap_level_used": 5, "events": []},
        "session": {"keeper": True, "reauths": 2, "authed_at_end": False},
        "chain": [{"engine": "nuclei-dast", "ran": True, "expected": True, "note": "3 findings"},
                  {"engine": "zap", "ran": False, "expected": True, "note": "skipped"}],
        "findings": [
            {"tool": "nuclei", "category": "sql-injection", "url": "http://app.local/login?next=1",
             "param": "next", "method": "GET", "evidence": "err-based", "verified": True,
             "payload": "1'", "detection": "error-based", "confidence": "firm", "repro": "curl ...",
             "raw_output": "{}", "evidence_log": [
                 {"label": "probe", "request": {"method": "GET", "url": "http://app.local/login?next=1'",
                  "headers": {"h": "v"}, "body": ""},
                  "response": {"status": 500, "headers": {}, "elapsed_ms": 40, "size": 12,
                               "body": "SQL syntax", "truncated": False}}]},
            {"tool": "passive", "category": "misconfiguration", "url": "http://app.local/",
             "param": None, "method": "GET", "evidence": "no CSP", "verified": True,
             "evidence_log": []},
        ],
    }


def _db(tmp_path):
    return str(tmp_path / "t.db")


def test_ingest_fidelity_and_enrichment(tmp_path):
    dbp = _db(tmp_path)
    con = store.connect(dbp)
    summ = store.ingest(_result(), "s1", con=con)
    assert summ["findings"] == 2
    assert summ["exchanges"] == 1
    row = store.scan_overview(con, "s1")
    assert row["urls_count"] == 3
    assert row["reauths"] == 2 and row["authed_at_end"] == 0 and row["sqlmap_level"] == 5
    # enrichment: sql-injection -> critical, CWE-89 (denormalised from VULN_META, not stored upstream)
    sqli = con.execute("SELECT severity,cwe,vtitle FROM findings WHERE category='sql-injection'").fetchone()
    assert sqli["severity"] == "critical" and sqli["cwe"] == "CWE-89"
    # evidence exploded
    assert con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1
    # probe engine chain preserved incl. a non-firing engine
    zap = con.execute("SELECT ran,expected FROM probes WHERE engine='zap'").fetchone()
    assert zap["ran"] == 0 and zap["expected"] == 1
    con.close()


def test_reingest_is_idempotent_and_carries_triage(tmp_path):
    dbp = _db(tmp_path)
    con = store.connect(dbp)
    store.ingest(_result(), "s1", con=con)
    fid = con.execute("SELECT id FROM findings WHERE category='sql-injection'").fetchone()[0]
    store.set_triage(con, fid, "confirmed")
    store.set_note(con, fid, "hand-verified")
    # re-ingest same scan
    store.ingest(_result(), "s1", con=con)
    assert con.execute("SELECT COUNT(*) FROM findings WHERE scan_id='s1'").fetchone()[0] == 2
    r = con.execute("SELECT triage_status,analyst_note FROM findings WHERE category='sql-injection'").fetchone()
    assert r["triage_status"] == "confirmed" and r["analyst_note"] == "hand-verified"
    con.close()


def test_frontier_hit_by_is_precise(tmp_path):
    # only URLs that a finding actually landed on (full-url match) are marked hit
    dbp = _db(tmp_path)
    con = store.connect(dbp)
    store.ingest(_result(), "s1", con=con)
    hits = con.execute("SELECT url,hit_by FROM frontier_urls WHERE hit_by IS NOT NULL").fetchall()
    urls = {h["url"] for h in hits}
    assert "http://app.local/login?next=1" in urls   # the sqli finding url
    assert "http://app.local/x?a=1&b=2" not in urls    # never hit -> not falsely claimed
    con.close()
