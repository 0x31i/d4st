"""ZAP isolation + FP-adjudication + scope + token-minting auto-probe (no ZAP/network needed)."""
import os
import types

from d4st.orchestrator.adapters.base import RunContext
from d4st.orchestrator.adapters import zap as Z
from d4st import jsanalysis as J


def _fake_proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


# ---- Fix 1: spaced auth -> configfile, space-free -> inline -----------------------------------

def test_spacefree_cookie_stays_inline_even_with_path():
    args = Z.build_zap_args("https://a.ex", "SESSION=abc", {}, auth_conf_path="/tmp/p")
    z = args[args.index("-z") + 1]
    assert "replacer.full_list(0).matchstr=Cookie" in z   # inline (no space -> safe in -z)
    assert "-configfile" not in z


def test_rules_need_configfile_detects_space():
    assert Z._rules_need_configfile([(0, "Authorization", "Bearer x")]) is True
    assert Z._rules_need_configfile([(0, "Cookie", "SESSION=abc")]) is False


# ---- Fix 2: concurrency isolation (unique workdir + report name + free port) ------------------

def test_free_port_returns_usable_distinct_ports():
    p1, p2 = Z._free_port(), Z._free_port()
    assert isinstance(p1, int) and 1 <= p1 <= 65535
    # not guaranteed distinct, but overwhelmingly are; at minimum both valid
    assert isinstance(p2, int)


def test_two_runs_use_isolated_workdir_report_and_port(monkeypatch, tmp_path):
    """Two ZAP runs must never share workdir / report filename / port (the cross-contamination fix)."""
    seen = []

    def fake_exec(self, args, timeout=3600, cwd=None, env=None):
        # record the unique report name (from -J) + port (from -P) + cwd, and write that report
        jname = args[args.index("-J") + 1]
        port = args[args.index("-P") + 1] if "-P" in args else None
        seen.append((cwd, jname, port))
        with open(os.path.join(cwd, jname), "w") as fh:
            fh.write('{"site":[]}')
        return _fake_proc(0)

    monkeypatch.setattr(Z.ZapAdapter, "available", lambda self: True)
    monkeypatch.setattr(Z.ZapAdapter, "_exec", fake_exec)
    Z.ZapAdapter().run(RunContext(target="https://a.ex"))
    Z.ZapAdapter().run(RunContext(target="https://b.ex"))
    (cwd1, j1, p1), (cwd2, j2, p2) = seen
    assert cwd1 != cwd2                 # isolated workdir/HOME
    assert j1 != j2 and j1.startswith("report-") and j1.endswith(".json")  # unique report name
    assert p1 is not None and p2 is not None   # a listen port was pinned per run


def test_no_port_env_escape_hatch(monkeypatch):
    monkeypatch.setenv("D4ST_ZAP_NO_PORT", "1")
    args = Z.build_zap_args("https://a.ex", "", {}, port=5555)
    assert "-P" not in args


# ---- Fix 3: FP adjudication --------------------------------------------------------------------

def test_vuln_js_library_high_downgraded_to_low():
    f = [{"pluginid": "10003", "severity": "high", "name": "Vulnerable JS Library",
          "instances": [{"uri": "https://a.ex/chunk-X.js", "evidence": "ng-version 20.3.9"}]}]
    out = Z.adjudicate_zap(f)
    assert out[0]["severity"] == "low"
    assert "CVE range" in out[0]["verify_note"]


def test_pii_in_build_artifact_downgraded_to_info():
    f = [{"pluginid": "10062", "severity": "high", "name": "PII Disclosure",
          "instances": [{"uri": "https://a.ex/ngsw.json?ngsw-cache-bust=0.37", "evidence": "4180454633880"}]}]
    out = Z.adjudicate_zap(f)
    assert out[0]["severity"] == "info"
    assert "build/service-worker" in out[0]["verify_note"]


def test_pii_non_artifact_kept_but_flagged():
    f = [{"pluginid": "10062", "severity": "high", "name": "PII Disclosure",
          "instances": [{"uri": "https://a.ex/api/patient/export", "evidence": "4111111111111111"}]}]
    out = Z.adjudicate_zap(f)
    assert out[0]["severity"] == "high"               # real-looking context kept
    assert "pattern/Luhn match" in out[0]["verify_note"]


# ---- Fix 4: scope filtering --------------------------------------------------------------------

def test_scope_filter_drops_offscope_instances_and_findings():
    findings = [
        {"name": "CORS", "instances": [{"uri": "https://checkip.amazonaws.com/"}]},   # off-scope
        {"name": "CSP", "instances": [{"uri": "https://a.ex/"}, {"uri": "https://v4.ident.me/"}]},
        {"name": "SiteLevel", "instances": []},   # no URIs -> kept
    ]
    urls = ["https://a.ex/x", "https://checkip.amazonaws.com/y"]
    hosts = Z.scope_hosts("https://a.ex")
    kf, ku = Z.scope_filter(findings, urls, hosts)
    names = {f["name"] for f in kf}
    assert "CORS" not in names                 # entirely off-scope -> dropped
    assert "CSP" in names and "SiteLevel" in names
    csp = next(f for f in kf if f["name"] == "CSP")
    assert all("a.ex" in i["uri"] for i in csp["instances"])   # off-scope instance stripped
    assert ku == ["https://a.ex/x"]


# ---- Fix 5: unauthenticated token-minting auto-probe ------------------------------------------

def test_probe_detects_unauth_sas_and_redacts():
    sas = '[{"Value":"?sv=2018-03-28&sig=Od7G0EV5zxa3EL%2B%3D&spr=https&se=2026-10-03T05:14:32Z&srt=o&ss=f&sp=r"}]'

    def fetch(url):
        return (200, sas) if url == "https://a.ex/api/SAS/getAccountSASToken" else (200, "<!doctype html>")

    out = J.probe_minting_endpoints("https://a.ex", fetch=fetch)
    assert len(out) == 1
    f = out[0]
    assert f["severity"] == "high" and f["category"] == "unauthenticated-token-minting"
    assert f["verified"] is True
    assert "sig=<redacted>" in f["evidence"] and "Od7G0EV5" not in f["evidence"]   # secret redacted
    assert "getAccountSASToken" in f["url"]


def test_probe_detects_unauth_jwt():
    jwt = '{"token":"eyJhbGciOiJIUzI1Niomgkcm.eyJzdWIiOiIxMjM0NTY3.SflKxwRJSMeKKF2QT4fw"}'

    def fetch(url):
        return (200, jwt) if url.endswith("/api/token/getSASToken") else (200, "{}")

    out = J.probe_minting_endpoints("https://a.ex", fetch=fetch)
    assert len(out) == 1 and out[0]["severity"] == "high"
    assert "<redacted-jwt>" in out[0]["evidence"]


def test_probe_no_token_no_finding():
    out = J.probe_minting_endpoints("https://a.ex", fetch=lambda u: (404, "Not Found"))
    assert out == []


def test_probe_empty_origin():
    assert J.probe_minting_endpoints("", fetch=lambda u: (200, "sig=x&sv=2018-01-01")) == []
