"""ZAP adapter: AJAX-spider deep-crawl tuning + auth injection in the invocation (no ZAP needed)."""
from d4st.orchestrator.adapters.zap import build_zap_args


def test_ajax_spider_enabled_and_tuned():
    args = build_zap_args("https://app.example", "", {})
    assert "-j" in args                                  # AJAX spider on
    z = args[args.index("-z") + 1]
    assert "ajaxSpider.maxCrawlDepth=10" in z
    assert "ajaxSpider.clickElemsOnce=false" in z        # click all elems -> exercises postbacks
    assert "ajaxSpider.maxDuration=10" in z


def test_ajax_depth_overridable():
    args = build_zap_args("https://app.example", "", {"zap_ajax_depth": 25, "zap_ajax_duration_min": 30})
    z = args[args.index("-z") + 1]
    assert "ajaxSpider.maxCrawlDepth=25" in z and "ajaxSpider.maxDuration=30" in z


def test_cookie_injected_when_present():
    args = build_zap_args("https://app.example", "SESSION=abc", {})
    z = args[args.index("-z") + 1]
    assert "replacer.full_list(0).matchstr=Cookie" in z
    assert "replacement=SESSION=abc" in z


def test_no_cookie_no_replacer():
    args = build_zap_args("https://app.example", "", {})
    z = args[args.index("-z") + 1]
    assert "replacer.full_list(0)" not in z


# ---- auth header injection (bearer/SPA) + failure surfacing ------------------------------

def test_authorization_header_goes_to_configfile_not_z():
    # `Bearer <jwt>` has a space -> inlining it in `-z` breaks zap-full-scan's space-split (rc=3).
    # With a configfile path, the auth rules go to `-configfile` and the bearer is NOT in `-z`.
    from d4st.orchestrator.adapters.zap import _auth_rules, _replacer_properties
    args = build_zap_args("https://app.example", "SESSION=abc", {},
                          headers={"Authorization": "Bearer JWT", "X-Env": "stg"},
                          auth_conf_path="/tmp/zap_auth.properties")
    z = args[args.index("-z") + 1]
    assert "-configfile /tmp/zap_auth.properties" in z
    assert "Bearer JWT" not in z                    # the space-bearing value never hits -z
    assert "replacer.full_list" not in z            # no inline replacer when using the configfile
    # the properties file (space-safe) carries both the cookie and the bearer
    props = _replacer_properties(_auth_rules("SESSION=abc",
                                             {"Authorization": "Bearer JWT", "X-Env": "stg"}))
    assert "replacer.full_list(0).matchstr=Cookie" in props
    assert "replacer.full_list(1).replacement=Bearer JWT" in props
    assert "matchstr=X-Env" in props


def test_bearer_only_session_still_injects_auth():
    # JWT/SPA session has no cookie — ZAP must still carry the bearer, via the configfile.
    args = build_zap_args("https://app.example", "", {},
                          headers={"Authorization": "Bearer JWT"},
                          auth_conf_path="/tmp/zap_auth.properties")
    z = args[args.index("-z") + 1]
    assert "-configfile /tmp/zap_auth.properties" in z
    assert "Bearer JWT" not in z


def test_duplicate_cookie_header_not_double_injected():
    args = build_zap_args("https://app.example", "SESSION=abc", {}, headers={"Cookie": "SESSION=abc"})
    z = args[args.index("-z") + 1]
    assert z.count("matchstr=Cookie") == 1  # cookie arg wins; the headers-dup is skipped


def test_zap_run_surfaces_error_when_no_report(tmp_path, monkeypatch):
    """A ZAP run that errors (rc>=3, no report) must report WHY, not a bland '0 alert(s)'."""
    from d4st.orchestrator.adapters.base import RunContext
    from d4st.orchestrator.adapters.zap import ZapAdapter

    ad = ZapAdapter()
    monkeypatch.setattr(ad, "available", lambda: True)

    class FakeProc:
        returncode = 3
        stdout = ""
        stderr = "FAIL: could not start ZAP (AJAX browser 'firefox-headless' not found)"

    monkeypatch.setattr(ad, "_exec", lambda *a, **k: FakeProc())
    monkeypatch.chdir(tmp_path)  # no report.json here
    res = ad.run(RunContext(target="https://app.example", options={}))
    assert res.ok is False
    assert "rc=3" in res.note
    assert "firefox-headless" in res.note  # the real reason is surfaced


def test_zap_run_clean_zero_alert_is_ok(tmp_path, monkeypatch):
    """A successful run that simply found nothing is ok=True, not a failure."""
    import json as _json
    from d4st.orchestrator.adapters.base import RunContext
    from d4st.orchestrator.adapters.zap import ZapAdapter

    ad = ZapAdapter()
    monkeypatch.setattr(ad, "available", lambda: True)

    import os as _os
    import types as _types

    def fake_exec(args, timeout=3600, cwd=None, env=None):
        jname = args[args.index("-J") + 1]            # the unique per-run report name
        with open(_os.path.join(cwd, jname), "w") as fh:
            fh.write(_json.dumps({"site": []}))
        return _types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ad, "_exec", fake_exec)
    res = ad.run(RunContext(target="https://app.example", options={}))
    assert res.ok is True
    assert "0 alert(s)" in res.note


# --- rc=3 "file based operation" fix: run in a writable workdir + HOME, surface the real error ---
import os
import types
from d4st.orchestrator.adapters.base import RunContext
from d4st.orchestrator.adapters.zap import ZapAdapter


def _fake_proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_zap_runs_in_writable_workdir_with_home(monkeypatch, tmp_path):
    """ZAP must execute with cwd + HOME pointed at a writable dir (the rc=3 file-op cause) and then
    find the report it writes there."""
    captured = {}

    def fake_exec(self, args, timeout=3600, cwd=None, env=None):
        captured["cwd"] = cwd
        captured["home"] = (env or {}).get("HOME")
        # ZAP writes its report into the cwd it was handed, under the UNIQUE -J name
        jname = args[args.index("-J") + 1]
        with open(os.path.join(cwd, jname), "w") as fh:
            fh.write('{"site":[{"alerts":[{"alert":"X","riskcode":"2","instances":'
                     '[{"uri":"https://app.example/a","method":"GET"}]}]}]}')
        return _fake_proc(returncode=0)

    monkeypatch.setattr(ZapAdapter, "available", lambda self: True)
    monkeypatch.setattr(ZapAdapter, "_exec", fake_exec)
    res = ZapAdapter().run(RunContext(target="https://app.example"))
    assert captured["cwd"] and os.path.isdir(captured["cwd"])        # ran in a real dir
    assert captured["home"] == captured["cwd"]                       # HOME made writable
    assert res.ok and len(res.findings) == 1                        # report found + parsed
    assert res.findings[0]["severity"] == "medium"


def test_zap_surfaces_file_op_error(monkeypatch):
    """When no report is produced, the note must carry ZAP's real multi-line error + rc, not a bland
    '0 alerts' (so rc=3 'A file based operation failed' is diagnosable)."""
    def fake_exec(self, args, timeout=3600, cwd=None, env=None):
        return _fake_proc(returncode=3,
                          stderr="starting ZAP\nA file based operation failed\nreport not written")

    monkeypatch.setattr(ZapAdapter, "available", lambda self: True)
    monkeypatch.setattr(ZapAdapter, "_exec", fake_exec)
    # ensure no stray report.json in cwd is picked up
    monkeypatch.setattr(os.path, "exists", lambda p: False)
    res = ZapAdapter().run(RunContext(target="https://app.example"))
    assert res.ok is False
    assert "rc=3" in res.note and "file based operation failed" in res.note
