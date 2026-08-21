from dastng.dom import _cookies_for


def test_cookies_parsed_for_playwright():
    cs = _cookies_for("security=low; PHPSESSID=abc123", "h.test")
    names = {c["name"]: c["value"] for c in cs}
    assert names == {"security": "low", "PHPSESSID": "abc123"}
    assert all(c["domain"] == "h.test" and c["path"] == "/" for c in cs)


def test_empty_cookie():
    assert _cookies_for("", "h.test") == []


def test_taint_harness_has_marker_and_sinks():
    from dastng.dom import _TAINT, _TAINT_HARNESS
    assert _TAINT in _TAINT_HARNESS
    for sink in ("document.cookie", "storage.setItem", "setAttribute", "innerHTML", "input.value"):
        assert sink in _TAINT_HARNESS
