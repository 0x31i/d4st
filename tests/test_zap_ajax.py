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
