from d4st.orchestrator.adapters import REGISTRY
from d4st.orchestrator.adapters._targets import candidate_urls
from d4st.orchestrator.adapters.commix import parse_commix
from d4st.orchestrator.adapters.dalfox import parse_dalfox
from d4st.orchestrator.adapters.sqlmap import parse_sqlmap
from d4st.orchestrator.adapters.zap import parse_zap


def test_registry_has_core_subset():
    for name in ("katana", "nuclei", "zap", "sqlmap", "dalfox", "commix"):
        assert name in REGISTRY, f"{name} adapter not registered"


def test_active_flags_gate_the_right_tools():
    # discovery/passive crawl is not active; scanners that fuzz are
    assert REGISTRY["katana"].active is False
    for name in ("nuclei", "zap", "sqlmap", "dalfox", "commix"):
        assert REGISTRY[name].active is True


def test_candidate_urls_filters_params_and_caps():
    urls = [
        "http://h/a?id=1",
        "http://h/b",            # no params -> dropped
        "http://h/c?q=x",
        "http://h/a?id=1",       # dup
    ]
    got = candidate_urls(urls, require_params=True)
    assert got == ["http://h/a?id=1", "http://h/c?q=x"]

    logs = []
    capped = candidate_urls(urls, require_params=True, cap=1, log=logs.append)
    assert len(capped) == 1
    assert any("COVERAGE CAP" in m for m in logs)


def test_parse_dalfox_json_array():
    sample = (
        '[{"type":"V","inject_type":"inHTML-URL","method":"GET","param":"name",'
        '"payload":"<script>alert(1)</script>","evidence":"12 line",'
        '"cwe":"CWE-79","severity":"High","message_str":"reflected"}]'
    )
    out = parse_dalfox(sample)
    assert len(out) == 1
    assert out[0]["param"] == "name" and out[0]["cwe"] == "CWE-79"


def test_parse_dalfox_jsonl_fallback():
    sample = '{"type":"V","param":"q"}\n{"type":"V","param":"id"}'
    out = parse_dalfox(sample)
    assert [o["param"] for o in out] == ["q", "id"]


def test_parse_dalfox_empty():
    assert parse_dalfox("") == []
    assert parse_dalfox("not json") == []


SQLMAP_OUT = """
[10:00:00] [INFO] testing URL 'http://dvwa/vulnerabilities/sqli/?id=1'
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,CONCAT(...)
---
"""


def test_parse_sqlmap_extracts_param_and_types():
    out = parse_sqlmap(SQLMAP_OUT)
    assert len(out) == 1
    f = out[0]
    assert f["param"] == "id" and f["place"] == "GET"
    assert "boolean-based blind" in f["types"]
    assert any("UNION query" in t for t in f["types"])


def test_parse_sqlmap_no_finding():
    assert parse_sqlmap("[INFO] all tested parameters do not appear to be injectable") == []


COMMIX_OUT = """
(!) Warning stuff
[+] Testing the (GET) 'ip' parameter for command injection.
The (GET) 'ip' parameter is vulnerable to results-based command injection technique.
"""


def test_parse_commix():
    out = parse_commix(COMMIX_OUT, url="http://dvwa/vulnerabilities/exec/?ip=1")
    assert len(out) == 1
    assert out[0]["param"] == "ip" and out[0]["place"] == "GET"
    assert out[0]["category"] == "command-injection"


ZAP_REPORT = {
    "site": [{
        "@name": "http://dvwa",
        "alerts": [
            {
                "pluginid": "40012", "alert": "Cross Site Scripting (Reflected)",
                "riskcode": "3", "confidence": "2", "cweid": "79",
                "desc": "XSS", "solution": "encode",
                "count": "1",
                "instances": [{"uri": "http://dvwa/x?name=1", "method": "GET",
                               "param": "name", "evidence": "<script>"}],
            },
            {
                "pluginid": "10038", "alert": "CSP Header Not Set",
                "riskcode": "1", "confidence": "2", "cweid": "693",
                "instances": [{"uri": "http://dvwa/", "method": "GET"}],
            },
        ],
    }]
}


def test_parse_zap_findings_and_urls():
    findings, urls = parse_zap(ZAP_REPORT)
    assert len(findings) == 2
    xss = next(f for f in findings if "Scripting" in f["name"])
    assert xss["severity"] == "high" and xss["cweid"] == "79"
    assert "http://dvwa/x?name=1" in urls
    assert "http://dvwa/" in urls


def test_parse_zap_empty():
    assert parse_zap({}) == ([], [])


def test_map_bounded_respects_ceiling_and_isolates_errors():
    """The per-URL fan-out helper must never exceed the caller's concurrency ceiling (that is
    the whole safety guarantee) and one item raising must not sink the batch."""
    import threading
    import time

    from d4st.orchestrator.adapters.base import map_bounded

    peak = {"cur": 0, "max": 0}
    lock = threading.Lock()

    def fn(x):
        with lock:
            peak["cur"] += 1
            peak["max"] = max(peak["max"], peak["cur"])
        time.sleep(0.01)
        with lock:
            peak["cur"] -= 1
        if x == 3:
            raise ValueError("boom")
        return x * 10

    errs = []
    res = map_bounded(fn, list(range(8)), workers=3, on_error=lambda e: errs.append(e))
    assert peak["max"] <= 3                       # never more concurrent than the ceiling
    assert sorted(r for r in res) == [0, 10, 20, 40, 50, 60, 70]   # 30 dropped by the error
    assert len(errs) == 1
    # workers clamps to len(items); empty is a no-op; workers=1 runs inline
    assert map_bounded(lambda x: x, [], workers=4) == []
    assert map_bounded(lambda x: x * 2, [5], workers=99) == [10]
