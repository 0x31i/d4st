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
    """Each test starts from a known-clean exclude state and restores it after. The active matcher
    is reset EXPLICITLY (reload-from-env keeps the current matcher when the env var is absent, by
    design — so a programmatic Config install is never silently wiped; tests must reset by hand)."""
    monkeypatch.delenv("D4ST_EXCLUDE_PATHS", raising=False)
    S.set_exclude_matcher("")
    yield
    monkeypatch.delenv("D4ST_EXCLUDE_PATHS", raising=False)
    S.set_exclude_matcher("")


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


def test_matcher_bad_regex_fails_closed():
    # FAIL-CLOSED: a malformed re: pattern must ABORT (raise), never silently run unprotected.
    with pytest.raises(S.ExcludeConfigError):
        S.ExcludePathMatcher("re:[unterminated,/capture")
    # and a bad pattern in the env aborts get_policy() too (the run cannot proceed)
    with pytest.raises(S.ExcludeConfigError):
        S.set_exclude_matcher("re:(unbalanced")


def test_matcher_inspects_path_and_query_and_decodes():
    m = S.ExcludePathMatcher("/capture")
    # percent-encoded separators must not slip past (%2F -> /)
    assert m.matches("http://t/api%2Fcapture/new")
    # match against the QUERY STRING, not just the path
    assert m.matches("http://t/index.php?next=/capture")
    # dot-segments collapsed
    assert m.matches("http://t/a/b/../../capture")
    # query-routed action: an app dispatching on ?do=capture
    mq = S.ExcludePathMatcher("re:[?&]do=capture")
    assert mq.matches("http://t/index?do=capture")
    assert mq.matches("http://t/index?x=1&do=capture&y=2")
    assert not mq.matches("http://t/index?do=list")


def test_matcher_glob_whole_path_and_star_both_ends():
    # a glob matches the WHOLE path+query, so /api/*/capture* needs a middle segment ...
    assert not S.ExcludePathMatcher("/api/*/capture*").matches("http://t/api/capture")
    assert S.ExcludePathMatcher("/api/*/capture*").matches("http://t/api/v2/capture/new")
    # ... while *capture* catches both
    g = S.ExcludePathMatcher("*capture*")
    assert g.matches("http://t/api/capture") and g.matches("http://t/api/v2/capture/new")


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


class _FakeClient:
    """Stand-in for httpx.Client (used by the active-depth dispatchers + formchecks as a context
    manager): records every request to the shared attempts list and never touches the network."""
    def __init__(self, attempts, *a, **kw):
        self._attempts = attempts

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def request(self, method, url, *a, **kw):
        self._attempts.append((str(method).upper(), url))
        return _FakeResp(url)

    def get(self, url, *a, **kw):
        self._attempts.append(("GET", url))
        return _FakeResp(url)

    def post(self, url, *a, **kw):
        self._attempts.append(("POST", url))
        return _FakeResp(url)

    def put(self, url, *a, **kw):
        self._attempts.append(("PUT", url))
        return _FakeResp(url)


class _FakeSession:
    """Minimal auth Session stand-in for the active-depth dispatchers."""
    def __init__(self):
        self.headers = {}
        self.session_storage = {"token": "x"}

    def cookie_header(self, _base=""):
        return ""


@pytest.fixture
def _record_http(monkeypatch):
    """Monkeypatch every httpx entrypoint the engine uses (module-level get/post/put/request AND
    httpx.Client) to RECORD (method, url) and return a benign fake response. Purely in-process —
    the tests assert there is no real/external egress."""
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
    monkeypatch.setattr(httpx, "Client", lambda *a, **kw: _FakeClient(attempts, *a, **kw))
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


# =============================================================================================
# ADVERSARIAL CANARIES — ported from the reviewer PoCs. Each previously-leaking dispatcher is run
# under the aggressive policy against a fixture with ONE excluded parameterized URL + one allowed
# one; the HTTP sender is recorded and we assert ZERO requests ever reach the excluded path.
# =============================================================================================
EXCL = "http://fixture.local/api/captures/create?target_url=http://evil.example"
ALLOW = "http://fixture.local/api/items/search?q=1"


def _hits(attempts, path_prefix):
    return [(m, u) for (m, u) in attempts if urlsplit(u).path.startswith(path_prefix)]


def _arm_aggressive(monkeypatch):
    monkeypatch.setenv("D4ST_EXCLUDE_PATHS", "/api/captures")
    pol = S.get_policy("aggressive")   # installs active matcher; proves precedence over aggressive
    assert pol.name == "aggressive" and pol.exclude_paths.matches(EXCL)
    return pol


def test_canary_active_depth_suite_never_hits_excluded(monkeypatch, _record_http):
    """run_host_header_injection / cspp / cache_poisoning / nosql / ldap / transformation / hpp /
    reflection / xpath — each over a frontier containing the excluded URL → ZERO requests to it."""
    import d4st.activetests as A
    _arm_aggressive(monkeypatch)
    sess = _FakeSession()
    base = "http://fixture.local/"
    urls = [EXCL, ALLOW]
    dispatchers = [
        A.run_host_header_injection, A.run_cspp_checks, A.run_cache_poisoning_checks,
        A.run_nosql_checks, A.run_ldap_checks, A.run_transformation_checks, A.run_hpp_checks,
        A.run_reflection_checks, A.run_xpath_checks, A.run_cors_checks, A.run_verb_tampering,
    ]
    for fn in dispatchers:
        try:
            fn(sess, base, urls, delay=0.0)
        except Exception as exc:  # noqa: BLE001 - a dispatcher may no-op on the fake, that's fine
            assert "excluded" not in str(exc).lower()
    leaked = _hits(_record_http, "/api/captures")
    assert leaked == [], f"active-depth suite LEAKED to excluded path: {leaked}"
    # NON-VACUOUS: the allowed URL WAS probed (so the recorder is actually intercepting and the
    # 'zero to excluded' result is a real carve-out, not a dead no-op).
    assert _hits(_record_http, "/api/items"), "no requests recorded at all — canary is vacuous"
    # and the fake stayed purely local (no external egress)
    assert all(urlsplit(u).hostname == "fixture.local" for (_m, u) in _record_http)


def test_canary_formsec_probe_reflection_does_not_submit_excluded(monkeypatch, _record_http):
    """formchecks.probe_reflection on HTML whose form action is excluded → no POST to it."""
    from d4st.formchecks import probe_reflection
    _arm_aggressive(monkeypatch)
    html = (
        '<form method="post" action="/api/captures/create">'
        '<input name="target_url" type="text"></form>'
        '<form method="post" action="/api/items/add">'
        '<input name="body" type="text"></form>'
    )
    probe_reflection("http://fixture.local/page", html, cookie="")
    assert _hits(_record_http, "/api/captures") == [], "formsec LEAKED a submit to excluded action"
    # the allowed form WAS submitted (no over-block)
    assert _hits(_record_http, "/api/items"), "formsec over-blocked the allowed form"


def test_canary_api_authz_tests_no_write_to_excluded(monkeypatch, _record_http):
    """run_api_authz_tests given an OpenAPI schema with a create + {id} write on an excluded path →
    no POST/PUT/PATCH write fired at the excluded path (registration + BOLA loops both guarded)."""
    import httpx

    def _body(props):
        schema_props = {p: {"type": "string"} for p in props}
        return {"requestBody": {"content": {"application/json": {"schema": {"properties": schema_props}}}}}

    schema = {
        "servers": [{"url": "http://fixture.local/"}],
        "paths": {
            "/api/captures/create": {"post": _body(["username", "password"])},
            "/api/captures/{id}": {"put": _body(["name"]), "get": {}},
            "/api/users": {"get": {}},
        },
    }
    # make the schema fetch return our spec, everything else benign (recorded)
    def _get(url, *a, **kw):
        _record_http.append(("GET", url))
        r = _FakeResp(url)
        r.json = lambda: schema if url.endswith("openapi.json") else {}
        return r
    monkeypatch.setattr(httpx, "get", _get)
    _arm_aggressive(monkeypatch)

    E.run_api_authz_tests("http://fixture.local/openapi.json", cookie="", fuzz_forms=True)
    writes_to_excluded = [(m, u) for (m, u) in _record_http
                          if m in ("POST", "PUT", "PATCH") and "/api/captures" in urlsplit(u).path]
    assert writes_to_excluded == [], f"api-authz LEAKED a write to excluded path: {writes_to_excluded}"


def test_canary_authz_matrix_never_hits_excluded(monkeypatch, _record_http):
    """Two-account BOLA matrix over a frontier with the excluded URL → ZERO requests to it."""
    from d4st.auth.authz import run_authz_matrix
    _arm_aggressive(monkeypatch)
    sa, sb = _FakeSession(), _FakeSession()
    try:
        run_authz_matrix(sa, sb, "http://fixture.local/", [EXCL, ALLOW], delay=0.0)
    except Exception:  # noqa: BLE001,S110 - fake session may short-circuit; we only assert on sends
        pass
    assert _hits(_record_http, "/api/captures") == [], "authz-matrix LEAKED to excluded path"


def test_jwt_and_ws_receive_exclude_filtered_frontier():
    """JWT/WS engines are fed the exclude-filtered frontier by the engine; prove the filter removes
    the excluded URL from exactly the list they receive (safety.filter_excluded)."""
    S.set_exclude_matcher("/api/captures")
    frontier = S.filter_excluded([EXCL, ALLOW], label="jwt/ws")
    assert EXCL not in frontier and ALLOW in frontier


def test_config_programmatic_install_enforces(monkeypatch):
    """Reconciled Config: building Config(exclude_paths=...) WITHOUT the env var still installs the
    active matcher, so the engine's policy-less gates enforce it (no latent fail-open)."""
    monkeypatch.delenv("D4ST_EXCLUDE_PATHS", raising=False)
    S.set_exclude_matcher("")
    assert not S.is_path_excluded(EXCL)
    Config(exclude_paths=["/api/captures"])          # __post_init__ installs it
    assert S.is_path_excluded(EXCL)
    assert S.is_write_action(EXCL, "GET") is True     # free-function gate now enforces it


# =============================================================================================
# RESIDUAL-CLOSURE CANARIES (defense-in-depth): all-methods consistency + internal backstops.
# =============================================================================================
def test_canary_api_authz_read_gets_never_hit_excluded(monkeypatch, _record_http):
    """api-authz BOLA victim-enumeration + read-back GETs must also be withheld from an excluded
    path — an excluded endpoint gets ZERO requests of ANY method (GET included)."""
    import httpx

    def _body(props):
        sp = {p: {"type": "string"} for p in props}
        return {"requestBody": {"content": {"application/json": {"schema": {"properties": sp}}}}}

    schema = {
        "servers": [{"url": "http://fixture.local/"}],
        "paths": {
            # create + read-back on the excluded path (drives the registration + read-back GET loop)
            "/api/captures/create": {"post": _body(["username", "password"])},
            "/api/captures/{id}": {"get": {}, "put": _body(["name"])},
            "/api/captures": {"get": {}},          # BOLA victim-enumeration collection GET
            # an allowed collection so the enumeration loop still runs somewhere
            "/api/users": {"get": {}},
        },
    }

    def _get(url, *a, **kw):
        _record_http.append(("GET", url))
        r = _FakeResp(url)
        r.json = lambda: schema if url.endswith("openapi.json") else {}
        return r
    monkeypatch.setattr(httpx, "get", _get)
    _arm_aggressive(monkeypatch)

    E.run_api_authz_tests("http://fixture.local/openapi.json", cookie="", fuzz_forms=True)
    hits = [(m, u) for (m, u) in _record_http
            if "/api/captures" in urlsplit(u).path]   # ANY method, incl. GET
    assert hits == [], f"api-authz LEAKED a request (any method) to excluded path: {hits}"
    # NON-VACUOUS: the allowed collection WAS enumerated (recorder is live; gate is real)
    assert any("/api/users" in urlsplit(u).path for (_m, u) in _record_http)


def _spy_filter_excluded(monkeypatch):
    """Wrap safety.filter_excluded to record the frontier it is handed + what it returns, so we can
    prove a dispatcher ran it internally (non-vacuous even when the engine bails early)."""
    import d4st.safety as _S
    calls = {"inputs": [], "outputs": []}
    real = _S.filter_excluded

    def _wrap(urls, **kw):
        out = real(urls, **kw)
        calls["inputs"].append(list(urls))
        calls["outputs"].append(list(out))
        return out
    monkeypatch.setattr(_S, "filter_excluded", _wrap)
    return calls


def test_canary_jwt_internal_backstop_with_raw_urls(monkeypatch, _record_http):
    """Prove the INTERNAL backstop (not just the engine filter): run_jwt_attacks with RAW urls →
    its own filter_excluded strips the excluded URL before any use, AND zero requests reach it."""
    from d4st import jwtattacks
    _arm_aggressive(monkeypatch)
    calls = _spy_filter_excluded(monkeypatch)

    class _JwtSession:
        def __init__(self):
            self.headers = {"Authorization": "Bearer aaa.bbb.ccc"}
            self.session_storage = {"t": "x"}

        def cookie_header(self, _b=""):
            return ""

    try:
        jwtattacks.run_jwt_attacks(_JwtSession(), "http://fixture.local/", [EXCL, ALLOW], delay=0.0)
    except Exception:  # noqa: BLE001,S110
        pass
    # the dispatcher ran its internal backstop on the raw frontier...
    assert any(EXCL in i for i in calls["inputs"]), "run_jwt_attacks did not run its internal filter"
    assert all(EXCL not in o for o in calls["outputs"]), "internal filter did not strip excluded URL"
    # ...and nothing leaked to the excluded path
    assert _hits(_record_http, "/api/captures") == [], "jwt internal backstop LEAKED"


def test_canary_ws_internal_backstop_with_raw_urls(monkeypatch, _record_http):
    """Prove the INTERNAL backstop: run_ws_tests with RAW urls → its own filter_excluded strips the
    excluded URL before use, AND zero requests reach it."""
    from d4st import wstests
    _arm_aggressive(monkeypatch)
    calls = _spy_filter_excluded(monkeypatch)
    try:
        wstests.run_ws_tests(_FakeSession(), "http://fixture.local/", [EXCL, ALLOW], delay=0.0)
    except Exception:  # noqa: BLE001,S110
        pass
    assert any(EXCL in i for i in calls["inputs"]), "run_ws_tests did not run its internal filter"
    assert all(EXCL not in o for o in calls["outputs"]), "internal filter did not strip excluded URL"
    assert _hits(_record_http, "/api/captures") == [], "ws internal backstop LEAKED"


def test_exclude_guard_filters_urls_as_keyword():
    """@_exclude_guard must filter `urls` whether positional OR keyword (no silent skip)."""
    import d4st.activetests as A
    S.set_exclude_matcher("/api/captures")
    seen = {}

    @A._exclude_guard
    def _probe(session, base, urls, **kw):
        seen["urls"] = urls
        return []

    _probe("s", "http://fixture.local/", urls=[EXCL, ALLOW])   # urls as KEYWORD
    assert EXCL not in seen["urls"] and ALLOW in seen["urls"]
    _probe("s", "http://fixture.local/", [EXCL, ALLOW])        # urls POSITIONAL
    assert EXCL not in seen["urls"] and ALLOW in seen["urls"]
