"""retire.js integration: JSON parser + graceful no-op when the binary is absent (no egress)."""
import os
import tempfile

from d4st.jsanalysis import VulnLib, parse_retirejs, run_retirejs

_SAMPLE = {
    "version": "5.2.3",
    "data": [
        {"file": "/tmp/js/00001_jquery.min.js",
         "results": [
             {"component": "jquery", "version": "1.8.3",
              "vulnerabilities": [
                  {"severity": "medium",
                   "identifiers": {"summary": "jQuery before 1.9.0 XSS", "CVE": ["CVE-2012-6708"]},
                   "info": ["https://example/adv"]},
                  {"severity": "high",
                   "identifiers": {"summary": "selector XSS", "CVE": ["CVE-2020-11022"]}},
              ]}]},
        {"file": "/tmp/js/00002_app.js", "results": []},
    ],
}


def test_parse_picks_component_version_and_top_severity():
    rows = parse_retirejs(_SAMPLE)
    assert len(rows) == 1
    r = rows[0]
    assert isinstance(r, VulnLib)
    assert r.library == "jquery" and r.version == "1.8.3"
    assert "[high]" in r.detail                       # top severity across the 2 vulns
    assert "CVE-2012-6708" in r.detail


def test_parse_defensive_on_junk():
    assert parse_retirejs({}) == []
    assert parse_retirejs(None) == []
    assert parse_retirejs({"data": "nope"}) == []
    assert parse_retirejs([{"results": [{"component": "x", "version": "1", "vulnerabilities": []}]}]) == []


def test_run_retirejs_noop_without_binary(monkeypatch):
    # Force "retire not installed" -> must return [] (never raise, never auto-install).
    monkeypatch.setattr("shutil.which", lambda _n: None)
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "a.js"), "w").close()
        assert run_retirejs(d) == []


def test_run_retirejs_noop_empty_dir():
    with tempfile.TemporaryDirectory() as d:
        assert run_retirejs(d) == []
