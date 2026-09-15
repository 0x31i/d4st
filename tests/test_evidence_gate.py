"""Header-hygiene applicability gate + evidence-integrity guarantees.

Regression cover for the class of bug where ZAP flags a 'missing security header' (e.g.
anti-clickjacking) on a 0-byte redirect response — an unframable page that cannot actually be
clickjacked. The gate re-evaluates each such finding against its REAL captured response and drops
the ones that don't apply, without ever dropping a finding it couldn't prove either way.
"""

from types import SimpleNamespace

from d4st.engagement import (_hygiene_kind, _is_synthetic_exchange, dedup_shell_hygiene,
                             gate_header_hygiene)


def _resp(status, headers, body):
    return {"label": "FULL request / response (Burp-grade capture)",
            "request": {"method": "GET", "url": "https://x/"},
            "response": {"status": status, "headers": headers, "body": body}}


_ZAP_PLACEHOLDER = {
    "label": "ZAP finding — affected request/response",
    "request": {"method": "GET", "url": "https://x/", "body": ""},
    "response": {"status": None, "headers": {}, "size": 0,
                 "body": "finding basis: The response does not protect against 'ClickJacking'"},
}


def _f(**kw):
    kw.setdefault("verified", True)
    kw.setdefault("verify_note", "")
    kw.setdefault("detection", "zap active scan")
    return SimpleNamespace(**kw)


def test_synthetic_exchange_detection():
    assert _is_synthetic_exchange(_ZAP_PLACEHOLDER) is True
    assert _is_synthetic_exchange(_resp(200, {"Content-Type": "text/html"}, "<html>")) is False
    # a genuine attack exchange with no status but an injected request body is preserved
    assert _is_synthetic_exchange({"request": {"body": "alg:none forged"},
                                   "response": {"status": None, "headers": {}}}) is False


def test_hygiene_kind_matches_header_checks():
    assert _hygiene_kind(_f(evidence="Anti-clickjacking Header missing X-Frame-Options"))[0] == "x-frame-options"
    assert _hygiene_kind(_f(evidence="X-Content-Type-Options nosniff missing"))[0] == "x-content-type-options"
    assert _hygiene_kind(_f(evidence="reflected XSS confirmed")) is None


def test_clickjacking_on_empty_redirect_is_dropped():
    # THE BUG: clickjacking flagged on a 302 with a 0-byte body -> not framable -> drop
    f = _f(category="misconfiguration", url="https://x/",
           evidence="Anti-clickjacking Header — missing X-Frame-Options",
           evidence_log=[_resp(302, {"Location": "/login"}, ""), _ZAP_PLACEHOLDER])
    kept, dropped = gate_header_hygiene([f])
    assert kept == [] and dropped == [f]


def test_clickjacking_on_real_html_is_kept():
    f = _f(category="misconfiguration", url="https://x/app", evidence="Anti-clickjacking Header missing",
           evidence_log=[_resp(200, {"Content-Type": "text/html; charset=utf-8"}, "<html>login</html>")])
    kept, _ = gate_header_hygiene([f])
    assert kept == [f]


def test_dropped_when_header_actually_present():
    f = _f(category="misconfiguration", url="https://x/app", evidence="Anti-clickjacking Header",
           evidence_log=[_resp(200, {"Content-Type": "text/html", "X-Frame-Options": "DENY"}, "<html>")])
    kept, dropped = gate_header_hygiene([f])
    assert dropped == [f]


def test_csp_frame_ancestors_satisfies_clickjacking():
    f = _f(category="misconfiguration", url="https://x/app", evidence="clickjacking",
           evidence_log=[_resp(200, {"Content-Type": "text/html",
                                     "Content-Security-Policy": "frame-ancestors 'none'"}, "<html>")])
    kept, dropped = gate_header_hygiene([f])
    assert dropped == [f]


def test_nosniff_missing_on_json_is_kept():
    f = _f(category="misconfiguration", url="https://x/api/x",
           evidence="X-Content-Type-Options header missing (nosniff)",
           evidence_log=[_resp(200, {"Content-Type": "application/json"}, '{"ok":1}')])
    kept, _ = gate_header_hygiene([f])
    assert kept == [f]


def test_no_captured_response_keeps_but_downgrades_verified():
    f = _f(category="misconfiguration", url="https://x/", evidence="clickjacking header missing",
           evidence_log=[_ZAP_PLACEHOLDER])
    kept, dropped = gate_header_hygiene([f])
    assert kept == [f] and dropped == []
    assert f.verified is None  # cannot prove -> not shipped as independently verified


def test_non_hygiene_finding_untouched():
    f = _f(category="xss", url="https://x/s?q=1", evidence="reflected XSS confirmed",
           evidence_log=[_resp(200, {"Content-Type": "text/html"}, "<script>alert(1)")])
    kept, dropped = gate_header_hygiene([f])
    assert kept == [f] and dropped == []
    assert f.verified is True  # untouched


def test_cacheable_not_dropped_when_header_present():
    # cache-control PRESENT but permissive is still a finding -> presence must NOT clear it
    f = _f(category="info-disclosure", url="https://x/app", evidence="cacheable HTTPS response",
           evidence_log=[_resp(200, {"Content-Type": "text/html", "Cache-Control": "public, max-age=60"}, "<html>")])
    kept, dropped = gate_header_hygiene([f])
    assert kept == [f] and dropped == []


def test_shell_dedup_collapses_identical_bodies():
    shell = "<html><body>SPA shell</body></html>"
    grp = [_f(category="misconfiguration", url=f"https://x/route/{i}", evidence="Anti-clickjacking Header missing",
              evidence_log=[_resp(200, {"Content-Type": "text/html"}, shell)]) for i in range(5)]
    kept, collapsed = dedup_shell_hygiene(grp)
    assert len(kept) == 1 and collapsed == 4
    assert getattr(kept[0], "affects_routes", None) and len(kept[0].affects_routes) == 5
    assert "site-wide" in kept[0].evidence


def test_shell_dedup_keeps_distinct_bodies_separate():
    a = _f(category="misconfiguration", url="https://x/a", evidence="clickjacking missing",
           evidence_log=[_resp(200, {"Content-Type": "text/html"}, "<html>PAGE A</html>")])
    b = _f(category="misconfiguration", url="https://x/b", evidence="clickjacking missing",
           evidence_log=[_resp(200, {"Content-Type": "text/html"}, "<html>PAGE B different</html>")])
    kept, collapsed = dedup_shell_hygiene([a, b])
    assert len(kept) == 2 and collapsed == 0
