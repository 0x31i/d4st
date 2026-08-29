"""C2 read/write API over the store, via FastAPI TestClient against a temp DB."""
import pytest

from dastng import store

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from dastng.server import create_app  # noqa: E402
from tests.test_store import _result  # reuse the synthetic engagement result


@pytest.fixture()
def client(tmp_path):
    dbp = str(tmp_path / "t.db")
    con = store.connect(dbp)
    store.ingest(_result(), "s1", con=con)
    con.close()
    return TestClient(create_app(dbp))


def test_read_endpoints(client):
    assert len(client.get("/api/scans").json()) == 1
    ov = client.get("/api/scans/s1").json()
    assert ov["n_findings"] == 2 and ov["reauths"] == 2
    assert len(ov["engines"]) == 2
    fs = client.get("/api/scans/s1/findings").json()
    assert len(fs) == 2 and fs[0]["severity"] == "critical"  # severity sort
    assert len(client.get("/api/scans/s1/findings?severity=critical").json()) == 1
    assert len(client.get("/api/scans/s1/frontier").json()) == 3
    assert len(client.get("/api/scans/s1/probes").json()) == 2
    assert len(client.get("/api/scans/s1/evidence").json()) == 1
    assert client.get("/api/scans/nope").status_code == 404


def test_finding_detail_has_nested_exchange(client):
    fid = client.get("/api/scans/s1/findings?severity=critical").json()[0]["id"]
    d = client.get(f"/api/findings/{fid}").json()
    assert d["cwe"] == "CWE-89" and len(d["evidence_log"]) == 1
    ex = d["evidence_log"][0]
    assert ex["request"]["method"] == "GET" and ex["response"]["status"] == 500


def test_raw_grid_union_and_filters(client):
    allrows = client.get("/api/scans/s1/raw?size=2000").json()
    kinds = {r["kind"] for r in allrows}
    assert {"finding", "url", "probe", "exchange"} <= kinds
    # 2 findings + 3 urls + 2 probes + 1 exchange = 8
    assert len(allrows) == 8
    assert len(client.get("/api/scans/s1/raw?kind=finding").json()) == 2
    assert len(client.get("/api/scans/s1/raw?kind=probe&status=skipped").json()) == 1  # zap didn't run
    assert len(client.get("/api/scans/s1/raw?q=sql").json()) >= 1


def test_write_back_triage_and_note(client):
    fid = client.get("/api/scans/s1/findings?severity=critical").json()[0]["id"]
    assert client.post(f"/api/findings/{fid}/triage", json={"status": "confirmed"}).status_code == 200
    assert client.post(f"/api/findings/{fid}/triage", json={"status": "bogus"}).status_code == 400
    client.post(f"/api/findings/{fid}/note", json={"note": "real"})
    back = client.get(f"/api/findings/{fid}").json()
    assert back["triage_status"] == "confirmed" and back["analyst_note"] == "real"


def test_report_rebuilds_from_store(client):
    html = client.get("/api/report/s1").text
    assert "dast-ng" in html and "grade" not in html.lower()


def test_live_endpoint(client, tmp_path, monkeypatch):
    # no progress file -> reports stored terminal status
    r = client.get("/api/scans/s1/live").json()
    assert r["status"] == "complete" and r["live"] is False
    # a progress checkpoint is streamed back verbatim
    pf = tmp_path / "prog.json"
    pf.write_text('{"status":"in-progress","last_stage":"zap","n_findings":4,"elapsed_s":42}')
    monkeypatch.setenv("DASTNG_PROGRESS_FILE", str(pf))
    r = client.get("/api/scans/s1/live").json()
    assert r["status"] == "in-progress" and r["n_findings"] == 4
