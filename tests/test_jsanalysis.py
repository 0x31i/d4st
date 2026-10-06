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


# ----- SPA API discovery (script_srcs + mine_api_endpoints) ---------------- #

import httpx  # noqa: E402

from d4st.jsanalysis import script_srcs, mine_api_endpoints  # noqa: E402


class _Resp:
    def __init__(self, text, url):
        self.text = text
        self.url = url


def test_script_srcs_same_host_js_only():
    html = ('<script src="/main.1a2b.js"></script>'
            '<script src="https://app.test/vendor.js"></script>'
            '<script src="https://cdn.other.com/x.js"></script>'
            '<script src="/styles.css"></script>'
            '<script>inline()</script>')
    out = script_srcs(html, "https://app.test/", "app.test")
    assert "https://app.test/main.1a2b.js" in out
    assert "https://app.test/vendor.js" in out
    assert all("other.com" not in u for u in out)       # off-host dropped
    assert all(not u.endswith(".css") for u in out)      # non-js dropped


def test_mine_api_endpoints_glues_shell_to_analyze(monkeypatch):
    import d4st.jsanalysis as J
    monkeypatch.setattr(httpx, "get",
                        lambda *a, **k: _Resp('<script src="/main.js"></script>', "https://app.test/"))
    monkeypatch.setattr(J, "analyze_js",
                        lambda js_urls, cookie, host, cap=30:
                        (["https://app.test/api/Auth/Get/", "/api/Users/List/",
                          "https://cdn.other.com/api/x"], []))
    eps = mine_api_endpoints("https://app.test/", host="app.test")
    assert "https://app.test/api/Auth/Get/" in eps
    assert "https://app.test/api/Users/List/" in eps       # path absolutized
    assert all("other.com" not in e for e in eps)          # off-host dropped


def test_mine_api_endpoints_no_scripts_returns_empty(monkeypatch):
    monkeypatch.setattr(httpx, "get",
                        lambda *a, **k: _Resp("<html>no scripts</html>", "https://app.test/"))
    assert mine_api_endpoints("https://app.test/", host="app.test") == []
