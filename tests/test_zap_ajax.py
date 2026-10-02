"""ZAP adapter: AJAX-spider deep-crawl tuning + auth injection in the invocation (no ZAP needed)."""
from d4st.orchestrator.adapters.zap import build_zap_args


def test_ajax_spider_enabled_and_tuned():
    args = build_zap_args("https://app.example", "", {})
    assert "-j" in args                                  # AJAX spider on
    z = args[args.index("-z") + 1]
    assert "ajaxSpider.maxCrawlDepth=10" in z
    assert "ajaxSpider.clickElemsOnce=false" in z        # click all elems -> exercises postbacks
    assert "ajaxSpider.maxDuration=10" in z


def test_ajax_depth_overridable():
    args = build_zap_args("https://app.example", "", {"zap_ajax_depth": 25, "zap_ajax_duration_min": 30})
    z = args[args.index("-z") + 1]
    assert "ajaxSpider.maxCrawlDepth=25" in z and "ajaxSpider.maxDuration=30" in z


def test_cookie_injected_when_present():
    args = build_zap_args("https://app.example", "SESSION=abc", {})
    z = args[args.index("-z") + 1]
    assert "replacer.full_list(0).matchstr=Cookie" in z
    assert "replacement=SESSION=abc" in z


def test_no_cookie_no_replacer():
    args = build_zap_args("https://app.example", "", {})
    z = args[args.index("-z") + 1]
    assert "replacer.full_list(0)" not in z


# ---- auth header injection (bearer/SPA) + failure surfacing ------------------------------

def test_authorization_header_injected_alongside_cookie():
    args = build_zap_args("https://app.example", "SESSION=abc",
                          {}, headers={"Authorization": "Bearer JWT", "X-Env": "stg"})
    z = args[args.index("-z") + 1]
    assert "replacer.full_list(0).matchstr=Cookie" in z
    assert "replacer.full_list(1).matchstr=Authorization" in z
    assert "replacement=Bearer JWT" in z
    assert "matchstr=X-Env" in z


def test_bearer_only_session_still_injects_auth():
    # JWT/SPA session has no cookie — ZAP must still carry the bearer (was scanned logged-out before)
    args = build_zap_args("https://app.example", "", {}, headers={"Authorization": "Bearer JWT"})
    z = args[args.index("-z") + 1]
    assert "replacer.full_list(0).matchstr=Authorization" in z


def test_duplicate_cookie_header_not_double_injected():
    args = build_zap_args("https://app.example", "SESSION=abc", {}, headers={"Cookie": "SESSION=abc"})
    z = args[args.index("-z") + 1]
    assert z.count("matchstr=Cookie") == 1  # cookie arg wins; the headers-dup is skipped


def test_zap_run_surfaces_error_when_no_report(tmp_path, monkeypatch):
    """A ZAP run that errors (rc>=3, no report) must report WHY, not a bland '0 alert(s)'."""
    from d4st.orchestrator.adapters.base import RunContext
    from d4st.orchestrator.adapters.zap import ZapAdapter

    ad = ZapAdapter()
    monkeypatch.setattr(ad, "available", lambda: True)

    class FakeProc:
        returncode = 3
        stdout = ""
        stderr = "FAIL: could not start ZAP (AJAX browser 'firefox-headless' not found)"

    monkeypatch.setattr(ad, "_exec", lambda *a, **k: FakeProc())
    monkeypatch.chdir(tmp_path)  # no report.json here
    res = ad.run(RunContext(target="https://app.example", options={}))
    assert res.ok is False
    assert "rc=3" in res.note
    assert "firefox-headless" in res.note  # the real reason is surfaced


def test_zap_run_clean_zero_alert_is_ok(tmp_path, monkeypatch):
    """A successful run that simply found nothing is ok=True, not a failure."""
    import json as _json
    from d4st.orchestrator.adapters.base import RunContext
    from d4st.orchestrator.adapters.zap import ZapAdapter

    ad = ZapAdapter()
    monkeypatch.setattr(ad, "available", lambda: True)

    class FakeProc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(ad, "_exec", lambda *a, **k: FakeProc())
    monkeypatch.chdir(tmp_path)
    (tmp_path / "report.json").write_text(_json.dumps({"site": []}))
    res = ad.run(RunContext(target="https://app.example", options={}))
    assert res.ok is True
    assert "0 alert(s)" in res.note
