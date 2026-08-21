import json

from dastng.scoring import categories as C
from dastng.scoring.burp import parse_burp
from dastng.scoring.normalize import (
    normalize_commix,
    normalize_dalfox,
    normalize_nuclei,
    normalize_sqlmap,
    normalize_zap,
)
from dastng.scoring.oracle import load_oracle, path_of
from dastng.scoring.score import build_matrix, matrix_to_dict, score_columns

# ----- categories -------------------------------------------------------------

def test_classify_by_cwe():
    assert C.classify(["CWE-89"], "") == C.SQL_INJECTION
    assert C.classify(["CWE-79"], "") == C.XSS
    assert C.classify(["CWE-78"], "") == C.COMMAND_INJECTION
    assert C.classify(["CWE-601"], "") == C.OPEN_REDIRECT


def test_classify_by_keyword():
    assert C.classify([], "SQL injection") == C.SQL_INJECTION
    assert C.classify([], "Cross Site Scripting (Reflected)") == C.XSS
    assert C.classify([], "OS Command Injection") == C.COMMAND_INJECTION
    assert C.classify([], "Remote File Inclusion") == C.FILE_INCLUSION
    assert C.classify([], "unknown thing") == C.OTHER


# ----- oracle -----------------------------------------------------------------

def test_dvwa_oracle_loads():
    o = load_oracle("dvwa")
    cats = o.categories()
    assert C.SQL_INJECTION in cats and C.XSS in cats and C.COMMAND_INJECTION in cats
    sqli = o.items_in(C.SQL_INJECTION)
    assert any(it.endpoint_path == "/vulnerabilities/sqli" and it.param == "id" for it in sqli)


def test_path_of():
    assert path_of("http://dvwa.local/vulnerabilities/sqli/?id=1") == "/vulnerabilities/sqli"
    assert path_of("/vulnerabilities/exec/") == "/vulnerabilities/exec"


# ----- normalizers ------------------------------------------------------------

def test_normalize_nuclei_cwe_and_url():
    line = json.dumps({
        "template-id": "xss-reflected",
        "info": {"name": "Reflected XSS", "severity": "high",
                 "classification": {"cwe-id": ["CWE-79"]}, "tags": ["xss"]},
        "matched-at": "http://dvwa.local/vulnerabilities/xss_r/?name=1",
    })
    out = normalize_nuclei(line)
    assert len(out) == 1
    assert out[0].category == C.XSS
    assert out[0].endpoint == "/vulnerabilities/xss_r"
    assert out[0].param == "name"


def test_normalize_dalfox():
    sample = json.dumps([{"param": "name", "cwe": "CWE-79",
                          "data": "http://dvwa.local/vulnerabilities/xss_r/?name=x"}])
    out = normalize_dalfox(sample)
    assert out[0].category == C.XSS and out[0].endpoint == "/vulnerabilities/xss_r"


def test_normalize_sqlmap_associates_url():
    text = (
        "[INFO] testing URL 'http://dvwa.local/vulnerabilities/sqli/?id=1'\n"
        "sqlmap identified the following injection point(s)\n"
        "Parameter: id (GET)\n    Type: boolean-based blind\n"
    )
    out = normalize_sqlmap(text)
    assert out[0].category == C.SQL_INJECTION
    assert out[0].endpoint == "/vulnerabilities/sqli"
    assert out[0].param == "id"


def test_normalize_commix():
    text = "The (GET) 'ip' parameter is vulnerable to results-based command injection technique."
    out = normalize_commix(text, url="http://dvwa.local/vulnerabilities/exec/?ip=1")
    assert out[0].category == C.COMMAND_INJECTION
    assert out[0].endpoint == "/vulnerabilities/exec"


def test_normalize_zap_expands_instances():
    report = {"site": [{"alerts": [{
        "alert": "SQL Injection", "riskcode": "3", "cweid": "89",
        "instances": [{"uri": "http://dvwa.local/vulnerabilities/sqli/?id=1",
                       "param": "id", "method": "GET"}],
    }]}]}
    out = normalize_zap(report)
    assert out[0].category == C.SQL_INJECTION and out[0].param == "id"


# ----- burp -------------------------------------------------------------------

BURP_XML = """<?xml version="1.0"?>
<issues>
  <issue><type>1</type><name>SQL injection</name><host>http://dvwa.local</host>
    <path>/vulnerabilities/sqli/</path><severity>High</severity></issue>
  <issue><type>2</type><name>Cross-site scripting (reflected)</name><host>http://dvwa.local</host>
    <path>/vulnerabilities/xss_r/</path><severity>High</severity></issue>
</issues>"""


def test_parse_burp():
    out = parse_burp(BURP_XML)
    cats = {f.category for f in out}
    assert C.SQL_INJECTION in cats and C.XSS in cats
    sqli = next(f for f in out if f.category == C.SQL_INJECTION)
    assert sqli.endpoint == "/vulnerabilities/sqli"


# ----- end-to-end scoring + matrix -------------------------------------------

def test_end_to_end_matrix_and_delta():
    o = load_oracle("dvwa")
    # pipeline detects sqli + xss(reflected) + cmdi; burp detects sqli only
    nuclei = normalize_nuclei(json.dumps({
        "info": {"name": "XSS", "classification": {"cwe-id": ["CWE-79"]}},
        "matched-at": "http://dvwa.local/vulnerabilities/xss_r/?name=1"}))
    sqlmap = normalize_sqlmap(
        "testing URL 'http://dvwa.local/vulnerabilities/sqli/?id=1'\n"
        "Parameter: id (GET)\n    Type: UNION query\n")
    commix = normalize_commix(
        "The (GET) 'ip' parameter is vulnerable to command injection.",
        url="http://dvwa.local/vulnerabilities/exec/?ip=1")
    burp = parse_burp(BURP_XML)  # sqli + xss

    scored = score_columns(o, {"nuclei": nuclei, "sqlmap": sqlmap,
                               "commix": commix, "burp": burp})
    order = ["nuclei", "sqlmap", "commix", "pipeline", "burp"]
    rows = {r.category: r for r in build_matrix(o, scored, order)}

    # command-injection: pipeline finds it, burp does not -> positive delta
    cmdi = rows[C.COMMAND_INJECTION]
    assert cmdi.recalls["pipeline"][0] == 1
    assert cmdi.recalls["burp"][0] == 0
    assert cmdi.delta is not None and cmdi.delta > 0

    # sql-injection: 2 oracle items (sqli + blind); pipeline detects the non-blind one
    sqli = rows[C.SQL_INJECTION]
    assert sqli.total == 2
    assert sqli.recalls["sqlmap"][0] == 1

    d = matrix_to_dict(o, scored, order)
    assert d["oracle"] == "dvwa"
    assert any(r["category"] == C.XSS for r in d["rows"])
