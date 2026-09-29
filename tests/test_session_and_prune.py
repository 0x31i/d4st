"""Session-token-in-URL passive check + the discovery/logout prune split.

Covers two coverage upgrades:
- passive.check_response flags session ids / credentials carried in the URL (CWE-598),
  in the query string and in a redirect Location, while staying low-FP on benign params.
- safety.is_session_destroying_endpoint is NARROW (logout only) so discovery can traverse
  authenticated content areas, while safety.is_auth_endpoint stays BROAD for the active-test
  gate (never fuzz a login/reset endpoint).
"""
from d4st import passive, report, safety


def _checks(findings):
    return [f for f in findings if f.check == "session-token-in-url"]


def test_session_id_in_query_flagged():
    f = passive.check_response("https://app.example/dash?jsessionid=ABC123&x=1", 200, {}, "", [])
    hits = _checks(f)
    assert len(hits) == 1
    assert hits[0].category == "weak-session"
    assert hits[0].severity == "medium"


def test_credential_in_query_flagged():
    f = passive.check_response("https://app.example/x?password=hunter2", 200, {}, "", [])
    assert _checks(f)


def test_token_in_redirect_location_flagged():
    f = passive.check_response(
        "https://app.example/go", 302, {"Location": "/home?access_token=xyz"}, "", [])
    assert _checks(f)


def test_benign_params_not_flagged():
    f = passive.check_response("https://app.example/search?q=hello&page=2&token=csrf", 200, {}, "", [])
    # generic 'token' is intentionally NOT in the curated list -> no FP
    assert not _checks(f)


def test_weak_session_category_resolves_meta():
    m = report._meta_for("weak-session")
    assert m["title"] != report.VULN_META["other"]["title"]
    assert "CWE-598" in m["cwe"]


def test_logout_is_session_destroying():
    assert safety.is_session_destroying_endpoint("https://a/Account/Logout")
    assert safety.is_session_destroying_endpoint("https://a/auth/signout")


def test_authed_content_area_not_pruned_from_discovery():
    # These merely CONTAIN auth-ish words; discovery must still be allowed to follow them.
    for u in ("https://a/Authorization/List", "https://a/PasswordVault/View", "https://a/AuthorList"):
        assert not safety.is_session_destroying_endpoint(u)


def test_login_still_active_test_gated():
    # Broad gate stays intact so we never actively fuzz auth endpoints (account-lockout safety).
    assert safety.is_auth_endpoint("https://a/login")
    assert safety.is_auth_endpoint("https://a/account/reset-password")
