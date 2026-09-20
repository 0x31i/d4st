from d4st.safety import (
    LockoutMonitor,
    Politeness,
    auth_endpoint_safe_to_test,
    is_auth_endpoint,
)


def test_auth_endpoint_get_nav_params_testable():
    # OWA logon.aspx?url=...&reason= — return-URL/nav params, safe to reflection-test read-only
    assert auth_endpoint_safe_to_test("https://h/owa/auth/logon.aspx", "GET", ["url", "reason"])
    assert auth_endpoint_safe_to_test("https://h/owa/auth/logon.aspx", "GET", ["replaceCurrent"])


def test_auth_endpoint_credential_params_blocked():
    assert not auth_endpoint_safe_to_test("https://h/login", "GET", ["username", "password"])
    assert not auth_endpoint_safe_to_test("https://h/login", "GET", ["token"])


def test_auth_endpoint_no_params_or_post_blocked():
    assert not auth_endpoint_safe_to_test("https://h/login", "GET", [])
    assert not auth_endpoint_safe_to_test("https://h/login", "POST", ["url"])


def test_auth_endpoints_excluded():
    for u in ["https://h/login.php", "https://h/Account/SignIn", "https://h/logout",
              "https://h/api/authenticate", "https://h/password/reset", "https://h/oauth/token"]:
        assert is_auth_endpoint(u), u


def test_non_auth_not_excluded():
    for u in ["https://h/vulnerabilities/sqli/", "https://h/api/records/search",
              "https://h/app/common/RecordSearch.html"]:
        assert not is_auth_endpoint(u), u


def test_politeness_tool_flags():
    p = Politeness(rps=2.0, concurrency=2, delay_ms=250)
    assert "-rl" in p.katana_flags() and "2" in p.katana_flags()
    assert "-rl" in p.nuclei_flags()
    assert "--delay" in p.sqlmap_flags()


def test_lockout_monitor_backs_off_then_halts():
    m = LockoutMonitor(max_strikes=2, backoff_s=0)
    assert m.observe(200, "https://h/app", "ok", had_session=True) is True   # clean
    assert m.observe(429, "https://h/app", "", had_session=True) is True      # strike 1 -> back off
    assert m.observe(200, "https://h/login", "", had_session=True) is False   # strike 2 -> halt
    assert m.tripped and len(m.events) == 2


def test_lockout_text_detected():
    m = LockoutMonitor(max_strikes=5, backoff_s=0)
    m.observe(200, "https://h/app", "Your account is locked. Try again later.", had_session=True)
    assert m.strikes == 1 and "lockout" in m.events[0].lower()


def test_browser_headers_ua_and_merge():
    from d4st.safety import BROWSER_UA, browser_headers
    h = browser_headers()
    assert "Mozilla/5.0" in h["User-Agent"] and h["User-Agent"] == BROWSER_UA
    assert "Accept" in h
    merged = browser_headers({"Cookie": "a=b"})
    assert merged["Cookie"] == "a=b" and "Mozilla/5.0" in merged["User-Agent"]
