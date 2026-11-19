"""D4ST_EXCLUDE_PATHS — operator path-exclusion carve-out.

Proves the safety-critical scope control: a path matching D4ST_EXCLUDE_PATHS is skipped by ALL
intrusive / state-changing / form-submitting request paths EVEN under the `aggressive` policy and
fuzz_forms=True, while plain GET discovery of the path is still allowed (so it is still mapped).
An empty/unset env must be exactly today's behavior (regression guard).

The CANARY test (bottom) runs the real form-fuzzer dispatch (engagement.probe_targets) against a
local in-process fixture — one "create-capture"-style POST form on an EXCLUDED path and one normal
POST form on an ALLOWED path — under the aggressive policy, with the HTTP sender monkeypatched to
RECORD every attempt (no real/external host is ever contacted). It asserts ZERO intrusive/submit
requests reached the excluded path, and the allowed path WAS submitted.
"""

from __future__ import annotations

import pytest

from d4st import safety as S
from d4st.config import Config


@pytest.fixture(autouse=True)
def _clean_exclude_env(monkeypatch):
    """Each test starts from a known-clean exclude state and restores the module matcher after."""
    monkeypatch.delenv("D4ST_EXCLUDE_PATHS", raising=False)
    S.reload_exclude_matcher_from_env()
    yield
    monkeypatch.delenv("D4ST_EXCLUDE_PATHS", raising=False)
    S.reload_exclude_matcher_from_env()


# --------------------------------------------------------------------------- matcher format ----
def test_matcher_substring_glob_regex():
    m = S.ExcludePathMatcher("/capture,/api/*/crawl*,re:/archive\\b")
    assert bool(m)
    # substring (no metachars): matches anywhere in the path, case-insensitive
    assert m.matches("http://t/api/v2/capture/new")
    assert m.matches("http://t/CAPTURE")
    # glob (fnmatch over the whole path)
    assert m.matches("http://t/api/x/crawling")
    assert not m.matches("http://t/api/crawl")           # glob needs the /*/ segment
    # regex
    assert m.matches("http://t/archive")
    assert not m.matches("http://t/archived-items")      # \b after 'archive'
    # unrelated path untouched
    assert not m.matches("http://t/products?id=1")


def test_matcher_empty_is_falsy_and_matches_nothing():
    m = S.ExcludePathMatcher("")
    assert not m
    assert not m.matches("http://t/anything/at/all")


def test_matcher_bad_regex_does_not_disable_rest():
    # a malformed re: pattern is skipped; the good substring still applies
    m = S.ExcludePathMatcher("re:[unterminated,/capture")
    assert m.matches("http://t/capture")


# ------------------------------------------------- (a) is_write_action rejects excluded paths ---
def test_is_write_action_rejects_excluded_even_get():
    S.set_exclude_matcher("/capture")
    # an excluded path is non-actionable for write/state-changing tests regardless of method
    assert S.is_write_action("http://t/api/capture", "GET") is True
    assert S.is_write_action("http://t/api/capture", "POST") is True
    assert S.is_state_changing("http://t/api/capture") is True
    # a NON-excluded GET stays a READ (no over-blocking / no surface starvation)
    assert S.is_write_action("http://t/products?id=1", "GET") is False


def test_is_write_action_without_exclude_is_unchanged():
    # regression: 'capture' is NOT a built-in destructive verb, so without the carve-out a POST to
    # it is NOT a write (this is exactly why the carve-out is needed).
    assert S.is_write_action("http://t/api/capture", "POST") is False
    # genuine destructive verbs still gate as before
    assert S.is_write_action("http://t/ConfirmOrder", "POST") is True
    assert S.is_write_action("http://t/user/delete", "DELETE") is True


# ------------------------------------- (c)+(precedence) exclusion wins over aggressive policy ----
def test_exclude_flows_into_aggressive_policy(monkeypatch):
    monkeypatch.setenv("D4ST_EXCLUDE_PATHS", "/capture,/crawl")
    pol = S.get_policy("aggressive")
    # aggressive intentionally does NOT skip state-changing — but the carve-out is independent
    assert pol.skip_state_changing is False
    assert pol.fuzz_forms is True
    assert pol.exclude_paths.matches("http://t/api/capture/new")
    assert not pol.exclude_paths.matches("http://t/products")
    # get_policy also installs the active matcher so the policy-less free functions honor it
    assert S.is_write_action("http://t/api/capture/new", "GET") is True


def test_get_policy_does_not_mutate_shared_policies(monkeypatch):
    monkeypatch.setenv("D4ST_EXCLUDE_PATHS", "/capture")
    S.get_policy("aggressive")
    # the shared module-level POLICIES entry must stay empty (a COPY carries the matcher)
    assert not S.POLICIES["aggressive"].exclude_paths


# --------------------------------------------------------- (d) empty env = no change at all -----
def test_empty_env_is_no_exclusion():
    pol = S.get_policy("aggressive")
    assert not pol.exclude_paths
    assert S.is_write_action("http://t/api/capture", "POST") is False
    assert not S.is_path_excluded("http://t/api/capture")


# ------------------------------------------------- config.py parses env into a compiled matcher --
def test_config_parses_exclude_paths(monkeypatch):
    monkeypatch.setenv("D4ST_EXCLUDE_PATHS", "/capture, /api/*/crawl* , re:/archive\\b")
    cfg = Config.from_env()
    assert cfg.exclude_paths == ["/capture", "/api/*/crawl*", "re:/archive\\b"]
    assert cfg.exclude_matcher.matches("http://t/api/v2/crawl/start")
    assert cfg.exclude_matcher.matches("http://t/archive")
    assert not cfg.exclude_matcher.matches("http://t/products")


def test_config_empty_env_no_exclude(monkeypatch):
    monkeypatch.delenv("D4ST_EXCLUDE_PATHS", raising=False)
    cfg = Config.from_env()
    assert cfg.exclude_paths == []
    assert not cfg.exclude_matcher


# ----------------------------------------------------- (e) ZAP exclude list contains patterns ----
def test_zap_exclude_regexes_contain_patterns():
    m = S.ExcludePathMatcher("/capture,re:/(create|new)-site")
    rx = m.zap_exclude_regexes()
    # substring/glob become '.*<escaped>.*'; regex is wrapped anchoring-free
    assert any("capture" in r for r in rx)
    assert any("create|new" in r for r in rx)
    # each entry is a single-quoted ZAP-plan regex string
    assert all(r.startswith("'") and r.endswith("'") for r in rx)


# =============================================================================================
# CANARY — real form-fuzzer dispatch against a local fixture, HTTP sender recorded (no network).
# =============================================================================================
from urllib.parse import urlsplit

from d4st import engagement as E


class _FakeResp:
    """Minimal httpx.Response stand-in: enough for the verify_* probes to run without a network."""
    def __init__(self, url="http://fixture.local/"):
        self.status_code = 200
        self.text = ""
        self.content = b""
        self.headers = {}
        self.url = url
        self.cookies = {}
        self.history = []

    def json(self):
        return {}


@pytest.fixture
def _record_http(monkeypatch):
    """Monkeypatch every httpx entrypoint the engine uses to RECORD (method, url) and return a
    benign fake response. Purely in-process — asserts there is no real/external egress."""
    import httpx
    attempts: list[tuple[str, str]] = []

    def _mk(method_name):
        def _fn(url, *a, **kw):
            attempts.append((method_name, url))
            return _FakeResp(url)
        return _fn

    def _request(method, url, *a, **kw):
        attempts.append((str(method).upper(), url))
        return _FakeResp(url)

    monkeypatch.setattr(httpx, "get", _mk("GET"))
    monkeypatch.setattr(httpx, "post", _mk("POST"))
    monkeypatch.setattr(httpx, "put", _mk("PUT"))
    monkeypatch.setattr(httpx, "request", _request)
    return attempts


def test_canary_excluded_form_gets_zero_intrusive_requests_allowed_is_submitted(
        monkeypatch, _record_http):
    # Fixture sitemap: one "create-capture"-style POST form on an EXCLUDED path (its mere
    # invocation would make the server fetch an external URL) + one normal POST form on an ALLOWED
    # path — both parameterized so the form-fuzzer would submit them.
    excluded_url = "http://fixture.local/api/captures/create"
    allowed_url = "http://fixture.local/app/comment/add"
    excluded = E.Target(url=excluded_url, method="POST", params=["target_url"],
                        values={"target_url": "x"})
    allowed = E.Target(url=allowed_url, method="POST", params=["body"], values={"body": "x"})

    # Drive it exactly as a real run would under the MOST aggressive policy.
    monkeypatch.setenv("D4ST_EXCLUDE_PATHS", "/api/captures")
    policy = S.get_policy("aggressive")        # installs the active matcher + proves precedence
    assert policy.name == "aggressive" and policy.fuzz_forms is True
    assert policy.exclude_paths.matches(excluded_url)

    findings = E.probe_targets([excluded, allowed], cookie="",
                               politeness=None, fuzz_forms=policy.fuzz_forms)
    assert isinstance(findings, list)

    excluded_path = urlsplit(excluded_url).path
    allowed_path = urlsplit(allowed_url).path
    hits_excluded = [(m, u) for (m, u) in _record_http
                     if urlsplit(u).path.startswith(excluded_path)]
    hits_allowed = [(m, u) for (m, u) in _record_http
                    if urlsplit(u).path.startswith(allowed_path)]

    # PROOF 1: ZERO intrusive/submit requests ever reached the excluded create-capture endpoint,
    # even though fuzz_forms=True under the aggressive policy.
    assert hits_excluded == [], f"exclude LEAKED — requests hit excluded path: {hits_excluded}"
    # PROOF 2: the allowed form WAS submitted (no over-blocking).
    assert hits_allowed, "allowed form was not submitted — carve-out over-blocked the whole scan"
    # PROOF 3: no request to any OTHER host (purely local fixture, no external egress).
    assert all(urlsplit(u).hostname == "fixture.local" for (_m, u) in _record_http)


def test_canary_without_exclude_both_forms_submitted(monkeypatch, _record_http):
    # Regression: with the carve-out unset, BOTH forms are fuzzed as before (no behavior change).
    monkeypatch.delenv("D4ST_EXCLUDE_PATHS", raising=False)
    S.get_policy("aggressive")   # installs an empty matcher
    cap = E.Target(url="http://fixture.local/api/captures/create", method="POST",
                   params=["target_url"], values={"target_url": "x"})
    other = E.Target(url="http://fixture.local/app/comment/add", method="POST",
                     params=["body"], values={"body": "x"})
    E.probe_targets([cap, other], cookie="", politeness=None, fuzz_forms=True)
    paths = {urlsplit(u).path for (_m, u) in _record_http}
    assert any(p.startswith("/api/captures") for p in paths)
    assert any(p.startswith("/app/comment") for p in paths)
