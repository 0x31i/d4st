import pyotp

from d4st.auth.profile import load_profile
from d4st.auth.session import Session
from d4st.auth.totp import totp_now
from d4st.auth.translators import (
    dalfox_cookie,
    header_args,
    nuclei_secrets,
    sqlmap_request_file,
)


def _session():
    return Session(
        name="t",
        origin="http://dvwa.local",
        storage_state={"cookies": [
            {"name": "PHPSESSID", "value": "abc123", "domain": "dvwa.local", "path": "/"},
            {"name": "security", "value": "low", "domain": "dvwa.local", "path": "/"},
            {"name": "other", "value": "x", "domain": "other.test", "path": "/"},
        ]},
        headers={"Authorization": "Bearer TOK"},
    )


def test_cookie_header_filters_by_host():
    s = _session()
    hdr = s.cookie_header("http://dvwa.local/index.php")
    assert "PHPSESSID=abc123" in hdr and "security=low" in hdr
    assert "other=x" not in hdr  # different domain excluded


def test_set_cookie_updates_in_place():
    s = _session()
    s.set_cookie("security", "high", domain="dvwa.local")
    vals = [c["value"] for c in s.cookies if c["name"] == "security"]
    assert vals == ["high"]  # replaced, not duplicated


def test_session_roundtrip(tmp_path):
    s = _session()
    p = tmp_path / "s.json"
    s.save(str(p))
    back = Session.load(str(p))
    assert back.cookie_header("dvwa.local") == s.cookie_header("dvwa.local")
    assert back.headers == s.headers


def test_header_args_includes_cookie_and_extra_headers():
    args = header_args(_session(), "http://dvwa.local/")
    assert "-H" in args
    joined = " ".join(args)
    assert "Cookie: " in joined and "PHPSESSID=abc123" in joined
    assert "Authorization: Bearer TOK" in joined


def test_dalfox_cookie():
    assert "PHPSESSID=abc123" in dalfox_cookie(_session(), "dvwa.local")


def test_nuclei_secrets_shape():
    doc = nuclei_secrets(_session(), domains=["dvwa.local"])
    types = {e["type"] for e in doc["static"]}
    assert "cookiesAuth" in types and "headersAuth" in types
    cookie_entry = next(e for e in doc["static"] if e["type"] == "cookiesAuth")
    assert cookie_entry["domains"] == ["dvwa.local"]
    keys = {c["key"] for c in cookie_entry["cookies"]}
    assert {"PHPSESSID", "security", "other"} <= keys


def test_sqlmap_request_file_carries_cookie():
    req = sqlmap_request_file(_session(), "http://dvwa.local/vulnerabilities/sqli/?id=1", "GET")
    assert req.startswith("GET /vulnerabilities/sqli/?id=1 HTTP/1.1")
    assert "Host: dvwa.local" in req
    assert "Cookie: " in req and "PHPSESSID=abc123" in req


def test_dvwa_profile_loads_and_resolves():
    prof = load_profile("dvwa")
    assert prof.type == "form"
    assert prof.creds() == ("admin", "password")
    assert prof.fmt(prof.login_url, "http://dvwa.local") == "http://dvwa.local/login.php"
    assert prof.validity_marker() == "Logout"
    assert prof.resolve_base("http://dvwa.local/") == "http://dvwa.local"


def test_totp_generates_valid_code():
    secret = pyotp.random_base32()
    code = totp_now(secret)
    assert pyotp.TOTP(secret).verify(code)
