from d4st.jsanalysis import detect_vuln_libs, extract_endpoints


def test_extract_api_endpoints():
    js = 'fetch("/api/Auth/GetInfo/"); var u="/app/common/RecordSearch.js";'
    eps = extract_endpoints(js, "https://app.test/app.js", "app.test")
    assert "https://app.test/api/Auth/GetInfo/" in eps
    # api endpoint should sort first
    assert eps[0].endswith("/api/Auth/GetInfo/")


def test_extract_skips_other_hosts():
    js = 'x="https://cdn.other.com/lib.js"; y="/local/thing.json"'
    eps = extract_endpoints(js, "https://app.test/a.js", "app.test")
    assert all("app.test" in e for e in eps)


def test_detect_vuln_jquery_from_filename():
    v = detect_vuln_libs("", "https://h/assets/lib/jquery-1.12.4.min.js")
    assert v and v[0].library == "jquery" and v[0].version == "1.12.4"


def test_detect_vuln_jquery_from_banner():
    v = detect_vuln_libs("/*! jQuery v3.4.1 | (c) JS Foundation */", "https://h/jquery.min.js")
    assert v and v[0].version == "3.4.1"


def test_recent_jquery_not_flagged():
    assert detect_vuln_libs("/*! jQuery v3.7.1 */", "https://h/jquery.min.js") == []


def test_detect_lodash_prototype_pollution():
    v = detect_vuln_libs("", "https://h/js/lodash-4.17.10.min.js")
    assert v and v[0].library == "lodash"


def test_semgrep_category_mapping():
    from d4st.jsanalysis import _semgrep_category
    assert _semgrep_category("dom-source-to-redirect", ["CWE-601"]) == "open-redirect"
    assert _semgrep_category("dom-source-to-data-sink", []) == "dom-data-manipulation"
    assert _semgrep_category("dom-source-to-html-sink", ["CWE-79"]) == "xss"
    assert _semgrep_category("hardcoded-secret", ["CWE-798"]) == "info-disclosure"


def test_parse_semgrep_json():
    import json

    from d4st.jsanalysis import parse_semgrep_json
    doc = json.dumps({"results": [{"check_id": "rules.dom-source-to-html-sink",
                      "path": "a.js", "start": {"line": 3},
                      "extra": {"message": "DOM XSS", "metadata": {"cwe": ["CWE-79"]}}}]})
    out = parse_semgrep_json(doc)
    assert out[0]["category"] == "xss" and out[0]["line"] == 3
