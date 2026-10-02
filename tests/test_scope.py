"""Engagement-scope enforcement: the canonical scope util + the Frontier scope gate that
keeps active/injection tools from ever attacking off-scope third-party hosts."""
import os

from d4st.orchestrator.frontier import Frontier
from d4st.scope import in_scope, in_scope_pred, scope_hosts

# The exact off-scope hosts the authed EHRM run wrongly attacked.
OFF = [
    "https://fonts.googleapis.com/css2?family=Roboto",
    "https://docs.google.com/viewer?url=x",
    "https://view.officeapps.live.com/op/view.aspx?src=x",
]
IN = [
    "https://ehrm3stage.fhcsd.org/",
    "https://ehrm3stage.fhcsd.org/api/Login/AuthUser?UserId=1",
]


def test_scope_hosts_defaults_to_target_host():
    assert scope_hosts("https://ehrm3stage.fhcsd.org/x", env="") == ["ehrm3stage.fhcsd.org"]


def test_scope_hosts_env_override_and_subdomain_match():
    hosts = scope_hosts("https://ehrm3stage.fhcsd.org/x", env="fhcsd.org, other.com")
    assert hosts == ["fhcsd.org", "other.com"]
    # a bare domain in scope also covers its subdomains
    assert in_scope("https://ehrm3stage.fhcsd.org/x", hosts) is True


def test_in_scope_excludes_third_party():
    hosts = ["ehrm3stage.fhcsd.org"]
    for u in OFF:
        assert in_scope(u, hosts) is False, u
    for u in IN:
        assert in_scope(u, hosts) is True, u


def test_in_scope_hostless_is_in_scope():
    # relative / host-less URLs resolve against the target → in-scope, never dropped
    assert in_scope("/api/x?q=1", ["ehrm3stage.fhcsd.org"]) is True


def test_in_scope_empty_hosts_means_no_restriction():
    assert in_scope("https://anything.example/x", []) is True


def test_frontier_drops_off_scope_keeps_in_scope():
    f = Frontier(in_scope=in_scope_pred(["ehrm3stage.fhcsd.org"]))
    assert f.add_url(IN[1]) is True
    for u in OFF:
        assert f.add_url(u) is False
    assert f.off_scope_dropped() == len(OFF)
    urls = f.urls()
    assert any("ehrm3stage.fhcsd.org" in u for u in urls)
    assert not any("googleapis" in u or "google.com" in u or "officeapps" in u for u in urls)
    assert f.stats()["off_scope_dropped"] == len(OFF)


def test_frontier_force_bypasses_scope_for_target():
    # the operator's explicit target is added even if a narrow D4ST_SCOPE_HOSTS would exclude it
    f = Frontier(in_scope=in_scope_pred(["other.com"]))
    assert f.add_url("https://ehrm3stage.fhcsd.org/", force=True) is True
    assert "https://ehrm3stage.fhcsd.org/" in f.urls()


def test_frontier_no_predicate_keeps_everything():
    f = Frontier()  # in_scope=None → legacy behavior, no filtering
    for u in OFF:
        assert f.add_url(u) is True
    assert f.off_scope_dropped() == 0


def test_workflow_scopes_frontier_end_to_end(monkeypatch):
    # A discovery adapter that returns off-scope third-party URLs must NOT leak them into the
    # frontier that detection (injection) adapters consume.
    from d4st.orchestrator import workflow as wf
    from d4st.orchestrator.adapters.base import AdapterResult

    seen = {}

    def fake_get_adapter(name):
        class A:
            active = False
            def run(self, ctx):
                if name == "disco":
                    return AdapterResult(tool=name, ok=True,
                                         discovered_urls=OFF + ["https://ehrm3stage.fhcsd.org/p?x=1"])
                seen["detect_targets"] = list(ctx.seed_urls)  # what injection would attack
                return AdapterResult(tool=name, ok=True)
        return A()

    monkeypatch.setattr(wf, "get_adapter", fake_get_adapter)
    spec = {"name": "t", "max_rounds": 1,
            "stages": [{"kind": "discovery", "tools": ["disco"]},
                       {"kind": "scan", "tools": ["detect"]}]}
    runner = wf.WorkflowRunner(spec, allow_active=True)
    res = runner.run("https://ehrm3stage.fhcsd.org/")
    targets = seen.get("detect_targets", [])
    assert not any("googleapis" in u or "google.com" in u or "officeapps" in u for u in targets), targets
    assert any("ehrm3stage.fhcsd.org" in u for u in targets)
    assert res.frontier_stats["off_scope_dropped"] == len(OFF)
