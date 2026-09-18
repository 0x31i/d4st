"""d4st -> Burp Suite XML export: validate the output parses under the SAME contract ASM-NG's
importburp endpoint uses (issues root, findall('issue'), base64 request/response, severity in
{High,Medium,Low,Information}). If this test passes, a d4st .burp.xml drops onto ASM-NG's BURP page.
"""
import base64
import xml.etree.ElementTree as ET

from d4st.export import to_burp_xml


def _sample_result():
    return {
        "target": "https://app.example.com",
        "findings": [
            {
                "category": "sql-injection", "url": "https://app.example.com/login?id=1",
                "param": "id", "method": "POST", "tool": "sqlmap",
                "evidence": "boolean-based blind on id", "verified": True,
                "detection": "differential response", "payload": "id=1' OR '1'='1",
                "verify_note": "replayed 2x", "repro": "curl -X POST ...",
                "evidence_log": [{
                    "label": "injection",
                    "request": {"method": "POST", "url": "https://app.example.com/login",
                                "headers": {"Host": "app.example.com"}, "body": "id=1'"},
                    "response": {"status": 500, "headers": {"Server": "nginx"}, "body": "SQL error"},
                }],
            },
            {  # refuted -> must be dropped from the client export
                "category": "xss", "url": "https://app.example.com/x", "verified": False,
            },
        ],
    }


def test_burp_xml_parses_under_asmng_contract(tmp_path):
    out = tmp_path / "d4st.burp.xml"
    n = to_burp_xml(_sample_result(), str(out))
    assert n == 1  # refuted finding excluded

    # --- replicate ASM-NG _processBurpImport parsing exactly ---
    root = ET.fromstring(out.read_text())
    assert root.tag == "issues"
    issues = root.findall("issue")
    assert len(issues) == 1
    iss = issues[0]

    assert iss.findtext("name")            # non-empty title
    assert iss.findtext("severity") in {"High", "Medium", "Low", "Information"}
    assert iss.findtext("severity") == "High"          # sql-injection (critical) -> Burp High
    assert iss.findtext("confidence") == "Certain"     # verified True

    host_el = iss.find("host")
    assert host_el is not None
    assert host_el.text == "https://app.example.com"
    assert iss.findtext("path").startswith("/login")

    rr = iss.find("requestresponse")
    req = rr.find("request")
    assert req.get("base64") == "true"
    decoded = base64.b64decode(req.text).decode("utf-8")
    assert "POST" in decoded and "app.example.com" in decoded
    resp = base64.b64decode(rr.find("response").text).decode("utf-8")
    assert "HTTP 500" in resp

    # detection prose carries the payload + d4st attribution
    detail = iss.findtext("issueDetail")
    assert "Payload:" in detail and "d4st" in detail
