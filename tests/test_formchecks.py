"""Form-security passive checks: cleartext credentials, missing CSRF, (parser for) reflection."""

from d4st.formchecks import _parse_forms, analyze_forms
from d4st.report import _meta_for

_HTTP_LOGIN = ('<form action="login.php" method="post">'
               '<input type="text" name="username"><input type="password" name="password">'
               '<input type="submit" name="Login"></form>')
_SECURE = ('<form action="/login" method="post"><input type="password" name="pw">'
           '<input type="hidden" name="csrf_token" value="abc"><input type="submit"></form>')


def test_cleartext_password_over_http():
    res = analyze_forms("http://host/login.php", _HTTP_LOGIN)
    checks = {r["check"] for r in res}
    assert "cleartext-credential-submission" in checks
    hi = next(r for r in res if r["check"] == "cleartext-credential-submission")
    assert hi["severity"] == "high"


def test_missing_csrf_on_post_form():
    res = analyze_forms("http://host/login.php", _HTTP_LOGIN)
    assert any(r["check"] == "csrf-token-missing" and r["severity"] == "medium" for r in res)


def test_https_form_with_token_is_clean():
    assert analyze_forms("https://host/login", _SECURE) == []


def test_password_form_over_https_not_cleartext():
    https_login = _HTTP_LOGIN.replace('action="login.php"', 'action="/login"')
    res = analyze_forms("https://host/login", https_login)
    assert not any(r["check"] == "cleartext-credential-submission" for r in res)  # https -> no cleartext
    assert any(r["check"] == "csrf-token-missing" for r in res)                   # still no token


def test_form_parser_extracts_fields():
    forms = _parse_forms(_HTTP_LOGIN)
    assert len(forms) == 1
    types = {t for _, t in forms[0]["fields"]}
    assert "password" in types and forms[0]["method"] == "post"


def test_severity_kb():
    assert _meta_for("cleartext-credential-submission")["severity"] == "high"
    assert _meta_for("reflected-input")["severity"] == "low"
