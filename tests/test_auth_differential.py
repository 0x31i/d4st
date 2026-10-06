"""Tests for the credential differential probe (d4st.auth.differential).

Covers the pure classifier and the raw (browser-independent) lens via an httpx MockTransport —
no Playwright/browser required. The browser lens (discover_and_probe) needs chromium and is
exercised live, not here.
"""

import httpx

from d4st.auth.differential import (
    Attempt,
    Verdict,
    build_raw_query,
    classify_verdict,
    raw_differential,
)


def _att(label, status=None, body="", visible="", logged_in=False):
    return Attempt(label=label, username=label, lens="raw", status=status, body=body,
                   visible_error=visible, logged_in=logged_in)


# ----------------------------- classifier --------------------------------- #

def test_identical_to_fake_is_not_provisioned():
    fake = _att("FAKE", 401, "Invalid Username/Password!")
    real = _att("alice", 401, "Invalid Username/Password!")
    assert classify_verdict(real, fake) is Verdict.NOT_PROVISIONED


def test_whitespace_differences_still_identical():
    fake = _att("FAKE", 500, "Invalid Username/Password!!!")
    real = _att("alice", 500, "  Invalid   Username/Password!!!  \n")
    assert classify_verdict(real, fake) is Verdict.NOT_PROVISIONED


def test_logged_in_wins():
    fake = _att("FAKE", 401, "Invalid Username/Password!")
    real = _att("admin", 200, '{"token":"x"}', logged_in=True)
    assert classify_verdict(real, fake) is Verdict.LOGGED_IN


def test_differs_with_locked_is_account_exists():
    fake = _att("FAKE", 401, "Invalid Username/Password!")
    real = _att("alice", 423, "Account is locked. Contact admin.")
    assert classify_verdict(real, fake) is Verdict.ACCOUNT_EXISTS_REFUSED


def test_differs_without_marker_is_distinct():
    fake = _att("FAKE", 401, "Invalid Username/Password!")
    real = _att("alice", 403, "Access from this IP is blocked.")
    assert classify_verdict(real, fake) is Verdict.DISTINCT_REJECTION


def test_no_api_reached_is_indeterminate():
    fake = _att("FAKE", None, "")
    real = _att("alice", None, "")
    assert classify_verdict(real, fake) is Verdict.INDETERMINATE


# ----------------------------- raw query build ---------------------------- #

def test_build_raw_query_splits_params():
    base, params = build_raw_query(
        "https://app.example.org/api/Login/AuthUser?username=zz&password=testpass&UserId=0&RFID=")
    assert base == "https://app.example.org/api/Login/AuthUser"
    assert set(params) == {"username", "password", "UserId", "RFID"}


def test_build_raw_query_no_query():
    base, params = build_raw_query("https://app.example.org/api/Common/AuthUser")
    assert base.endswith("/api/Common/AuthUser") and params == {}


# ----------------------------- raw differential --------------------------- #

def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), base_url="https://app.example.org")


def test_raw_differential_all_rejected_means_not_provisioned():
    # Server rejects everyone identically — the universal "weak password, wrong username" case.
    def handler(request):
        return httpx.Response(401, text="Invalid Username/Password!")

    endpoint = "https://app.example.org/api/Common/AuthUser"
    _, template = build_raw_query(endpoint + "?strEmail=zz&strPassword=testpass&intUserId=0")
    with _client(handler) as c:
        probe = raw_differential(c, endpoint, template,
                                 [("alice", "testpass"), ("bob", "testpass")],
                                 method="GET")
    assert probe.raw_verdicts["alice"] is Verdict.NOT_PROVISIONED
    assert probe.raw_verdicts["bob"] is Verdict.NOT_PROVISIONED
    # FAKE baseline + 2 creds = 3 attempts
    assert len(probe.attempts) == 3


def test_raw_differential_detects_a_real_login():
    # Only the provisioned user with the right password gets a 200 token response.
    def handler(request):
        p = request.url.params
        user = p.get("strEmail", "")
        pw = p.get("strPassword", "")
        if user == "realuser" and pw == "testpass":
            return httpx.Response(200, text='{"JWTToken":"abc.def.ghi","ok":true}')
        return httpx.Response(401, text="Invalid Username/Password!")

    endpoint = "https://app.example.org/api/Common/AuthUser"
    _, template = build_raw_query(endpoint + "?strEmail=zz&strPassword=testpass&intUserId=0")
    with _client(handler) as c:
        probe = raw_differential(c, endpoint, template,
                                 [("realuser", "testpass"), ("nobody", "testpass")],
                                 method="GET")
    assert probe.raw_verdicts["realuser"] is Verdict.LOGGED_IN
    assert probe.raw_verdicts["nobody"] is Verdict.NOT_PROVISIONED


def test_raw_differential_substitutes_username_and_password():
    seen = []

    def handler(request):
        seen.append(dict(request.url.params))
        return httpx.Response(401, text="nope")

    endpoint = "https://app.example.org/api/Login/AuthUser"
    _, template = build_raw_query(endpoint + "?username=zz&password=pw&UserId=0&RFID=")
    with _client(handler) as c:
        raw_differential(c, endpoint, template, [("alice", "testpass")], method="GET")
    # baseline uses the fake user; the real attempt uses alice/testpass; UserId stays 0.
    assert seen[0]["username"].startswith("zz_nouser")
    assert seen[1]["username"] == "alice" and seen[1]["password"] == "testpass"
    assert seen[1]["UserId"] == "0"


# ----- JSON serialization round-trip (probe --json must be valid JSON) ------ #

import json  # noqa: E402

from d4st.auth.differential import AppProbe  # noqa: E402


def test_probe_as_dict_json_roundtrips_with_nasty_body():
    # Raw login-API bodies carry newlines, backslashes, and markup-looking brackets; the
    # emitted JSON must still parse (the bug: console.print wrapped/ate these -> invalid JSON).
    nasty = 'Test Account [ADMIN]<img src=x>\r\n{"path":"C:\\\\x"}\tTAB\x07bell'
    probe = AppProbe(target="https://app.test/", api_endpoint="https://app.test/api/Login/")
    probe.attempts.append(Attempt(label="alice", username="alice", lens="browser",
                                  status=200, body=nasty, visible_error=nasty, logged_in=True))
    probe.verdicts["alice"] = Verdict.LOGGED_IN
    probe.raw_verdicts["alice"] = Verdict.LOGGED_IN
    probe.notes.append("node[with]brackets")

    emitted = json.dumps(probe.as_dict(), indent=2)   # same call the CLI makes
    back = json.loads(emitted)                         # must not raise

    assert back["verdicts"]["alice"] == "LOGGED_IN"     # enum -> string
    assert back["raw_verdicts"]["alice"] == "LOGGED_IN"
    assert back["attempts"][0]["body"] == nasty        # content preserved exactly
    assert back["target"] == "https://app.test/"
