from d4st.passive import check_response


def _checks(**kw):
    d = dict(url="https://h/", status=200, headers={}, body="", set_cookies=[], cors_acao=None)
    d.update(kw)
    return {f.check for f in check_response(**d)}


def test_hsts_flagged_on_https_without_header():
    assert "hsts-not-enforced" in _checks(headers={"Content-Type": "text/html; charset=utf-8"})


def test_hsts_not_flagged_when_present():
    assert "hsts-not-enforced" not in _checks(
        headers={"Strict-Transport-Security": "max-age=31536000", "X-Frame-Options": "DENY",
                 "Content-Security-Policy": "default-src 'self'", "Referrer-Policy": "no-referrer"})


def test_clickjacking_and_csp():
    c = _checks(headers={"Content-Type": "text/html"})
    assert "clickjacking" in c and "csp-missing" in c


def test_clickjacking_suppressed_by_frame_ancestors():
    assert "clickjacking" not in _checks(
        headers={"Content-Security-Policy": "frame-ancestors 'self'"})


def test_cookie_flags():
    c = _checks(headers={}, set_cookies=["SID=abc; Path=/"])
    assert {"cookie-no-secure", "cookie-no-httponly", "cookie-no-samesite"} <= c


def test_cookie_flags_ok_when_set():
    c = _checks(headers={}, set_cookies=["SID=abc; Secure; HttpOnly; SameSite=Strict"])
    assert "cookie-no-httponly" not in c and "cookie-no-secure" not in c


def test_cors_reflection():
    assert "cors-misconfig" in _checks(cors_acao="https://evil.example")


def test_charset_missing():
    assert "no-charset" in _checks(headers={"Content-Type": "text/html"}, body="<html>")


def test_version_disclosure():
    assert "version-disclosure" in _checks(headers={"Server": "Apache/2.4.68"})


def test_path_relative_css():
    body = '<link rel="stylesheet" href="styles/main.css">'
    assert "path-relative-css" in _checks(headers={"Content-Type": "text/html"}, body=body)
