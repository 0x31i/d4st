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


def test_hsts_weak_short_maxage():
    c = _checks(headers={"Strict-Transport-Security": "max-age=3600"})
    assert "hsts-weak" in c and "hsts-not-enforced" not in c


def test_hsts_strong_not_flagged_weak():
    c = _checks(headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})
    assert "hsts-weak" not in c and "hsts-not-enforced" not in c


def test_mixed_content_flagged():
    body = '<script src="http://cdn.example/x.js"></script>'
    assert "mixed-content" in _checks(headers={"Content-Type": "text/html"}, body=body)


def test_mixed_content_https_subresource_ok():
    body = '<script src="https://cdn.example/x.js"></script>'
    assert "mixed-content" not in _checks(headers={"Content-Type": "text/html"}, body=body)


def test_csp_weak_policy_flags_script_style_form():
    # weak CSP like islclinic.com: wildcard default + unsafe-inline, no form-action
    c = _checks(headers={"Content-Security-Policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'"})
    assert "csp-allows-untrusted-script" in c
    assert "csp-allows-untrusted-style" in c        # style-src falls back to default-src *
    assert "csp-allows-form-hijacking" in c
    assert "csp-missing" not in c


def test_csp_malformed_directive():
    c = _checks(headers={"Content-Security-Policy": "default-src 'self'; frobnicate foo; form-action 'self'"})
    assert "csp-malformed" in c


def test_csp_strong_policy_clean():
    strong = ("default-src 'self'; script-src 'self'; style-src 'self'; "
              "form-action 'self'; frame-ancestors 'none'")
    c = _checks(headers={"Content-Security-Policy": strong, "X-Frame-Options": "DENY"})
    assert not any(x.startswith("csp-") for x in c), c


def test_cross_domain_script_include():
    body = '<script src="https://cdn.thirdparty.io/lib.js"></script>'
    assert "cross-domain-script-include" in _checks(headers={"Content-Type": "text/html"}, body=body)


def test_cross_domain_script_protocol_relative():
    # protocol-relative //host/ (common for CDNs like wsimg.com) must be caught
    body = '<script src="//img1.wsimg.com/widgets/UX.js"></script>'
    assert "cross-domain-script-include" in _checks(headers={"Content-Type": "text/html"}, body=body)


def test_csp_no_style_src_flags_untrusted_style():
    # CSP with only frame-ancestors => no style-src/default-src => untrusted styles unrestricted
    c = _checks(headers={"Content-Security-Policy": "frame-ancestors 'self' *.godaddy.com"})
    assert "csp-allows-untrusted-style" in c


def test_csp_permissive_frame_ancestors_flags_clickjacking():
    c = _checks(headers={"Content-Security-Policy": "frame-ancestors 'self' godaddy.com *.godaddy.com"})
    assert "csp-allows-clickjacking" in c


def test_csp_strict_frame_ancestors_no_clickjacking():
    c = _checks(headers={"Content-Security-Policy":
                         "default-src 'self'; script-src 'self'; style-src 'self'; "
                         "form-action 'self'; frame-ancestors 'none'"})
    assert "csp-allows-clickjacking" not in c


def test_same_origin_script_not_flagged():
    body = '<script src="/local/app.js"></script>'
    assert "cross-domain-script-include" not in _checks(headers={"Content-Type": "text/html"}, body=body)
