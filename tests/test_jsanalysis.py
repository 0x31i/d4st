from dastng.jsanalysis import detect_vuln_libs, extract_endpoints


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
