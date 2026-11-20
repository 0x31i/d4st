"""Subdomain discovery front-end: enumeration union/dedup/wildcard-strip, wildcard DNS
filtering, scope-list derivation, graceful skip of absent binaries, and a CLI smoke test.

All offline — every source and resolver is mocked; no network, no real DNS, no real binaries.
"""
import json

import pytest
from click.testing import CliRunner

import d4st.discovery as disco
from d4st.discovery import (
    DiscoveryResult,
    HostRecord,
    LIVE,
    NXDOMAIN,
    RESOLVES_DEAD,
    _enumerate,
    _wildcards_stripped,
    discover_subdomains,
)

DOMAIN = "example.com"

# A crt.sh JSON fixture: multi-SAN name_value, wildcards, dupes, an out-of-scope SAN.
CRTSH_JSON = [
    {"name_value": "app.example.com\nwww.example.com", "common_name": "app.example.com"},
    {"name_value": "*.example.com"},
    {"name_value": "api.example.com"},
    {"name_value": "API.EXAMPLE.COM"},           # case dupe
    {"name_value": "cdn.unrelated.net"},          # out of scope -> dropped
    {"name_value": "legacy.example.com"},
]


def _install_sources(monkeypatch, *, crtsh, subfinder=None, amass=None):
    """Replace the module source registry with controlled callables."""
    srcs = [disco._Source("crtsh", lambda d, *, timeout=0: crtsh)]
    if subfinder is not None:
        srcs.append(disco._Source("subfinder", lambda d, *, timeout=0: subfinder))
    if amass is not None:
        srcs.append(disco._Source("amass", lambda d, *, timeout=0: amass, deep_only=True))
    monkeypatch.setattr(disco, "_SOURCES", srcs)


# ── enumeration: union / dedup / wildcard-strip / scope ──────────────────────


def test_wildcards_stripped_basic():
    out = _wildcards_stripped(
        ["*.example.com", "App.Example.com ", "x.example.com.", "other.net", "a@b", "h/p"],
        DOMAIN,
    )
    # wildcard stripped to apex, lowercased, trailing dot removed, off-scope & junk dropped
    assert out == {"example.com", "app.example.com", "x.example.com"}


def test_enumerate_unions_and_dedups_crtsh_and_subfinder(monkeypatch):
    _install_sources(monkeypatch, crtsh=["app.example.com", "www.example.com"],
                     subfinder=["api.example.com", "app.example.com"])  # app.* overlaps
    names, used = _enumerate(DOMAIN, deep=False, timeout=1)
    assert names == ["api.example.com", "app.example.com", "example.com", "www.example.com"]
    assert set(used) == {"crtsh", "subfinder"}  # both contributed


def test_enumerate_with_crtsh_fixture(monkeypatch):
    # feed the raw crt.sh name_value strings (as the source would return them)
    raw = []
    for row in CRTSH_JSON:
        raw += [p for p in row["name_value"].splitlines()]
        if row.get("common_name"):
            raw.append(row["common_name"])
    _install_sources(monkeypatch, crtsh=raw)
    names, _ = _enumerate(DOMAIN, deep=False, timeout=1)
    assert names == ["api.example.com", "app.example.com", "example.com",
                     "legacy.example.com", "www.example.com"]
    assert "cdn.unrelated.net" not in names         # off-scope SAN dropped
    assert "*.example.com" not in names             # wildcard stripped


def test_enumerate_deep_only_source_gated(monkeypatch):
    _install_sources(monkeypatch, crtsh=["app.example.com"], amass=["deep.example.com"])
    shallow, _ = _enumerate(DOMAIN, deep=False, timeout=1)
    assert "deep.example.com" not in shallow
    deep, used = _enumerate(DOMAIN, deep=True, timeout=1)
    assert "deep.example.com" in deep and "amass" in used


def test_enumerate_source_failure_is_skipped(monkeypatch):
    def boom(d, *, timeout=0):
        raise RuntimeError("crt.sh 502")
    monkeypatch.setattr(disco, "_SOURCES", [
        disco._Source("crtsh", boom),
        disco._Source("subfinder", lambda d, *, timeout=0: ["api.example.com"]),
    ])
    names, used = _enumerate(DOMAIN, deep=False, timeout=1)
    # pipeline survives a broken source and still returns the good one (+ apex)
    assert names == ["api.example.com", "example.com"]
    assert used == ["subfinder"]


# ── resolve + wildcard filtering ─────────────────────────────────────────────


def _fake_resolve_factory(table, wildcard_ip="10.0.0.9"):
    """Return a resolver fn; any name not in `table` and not the wildcard random probe is NXDOMAIN.
    Random wildcard-probe names (20-char) resolve to the wildcard IP."""
    def resolve(name):
        label = name.split(".")[0]
        if len(label) == 20 and label.isalnum():   # the random wildcard-detection probe
            return [wildcard_ip], None
        return table.get(name, ([], None))
    return resolve


def _run_pipeline(monkeypatch, *, names, table, wildcard=True, probe_live=None):
    """Drive discover_subdomains with mocked sources, resolver, and probe."""
    _install_sources(monkeypatch, crtsh=names)
    wc_ip = "10.0.0.9" if wildcard else None
    resolve = _fake_resolve_factory(table, wildcard_ip=wc_ip or "203.0.113.1")
    if not wildcard:
        # no wildcard: the random wildcard-detection probe resolves to nothing
        def resolve(name):  # noqa: F811
            label = name.split(".")[0]
            if len(label) == 20 and label.isalnum():
                return [], None
            return table.get(name, ([], None))
    monkeypatch.setattr(disco, "_resolver_fn", lambda resolvers, timeout: resolve)

    live_set = set(probe_live or [])

    def fake_probe(host, *, timeout):
        cls = LIVE if host in live_set else RESOLVES_DEAD
        return [{"scheme": "https", "url": f"https://{host}/", "status": 200 if cls == LIVE else None,
                 "final_url": f"https://{host}/", "server": "nginx" if cls == LIVE else None,
                 "title": None, "classification": cls}]
    monkeypatch.setattr(disco, "_probe_host", fake_probe)
    return discover_subdomains(DOMAIN, resolvers=None)


def test_wildcard_only_names_are_dropped(monkeypatch):
    # app -> real IP; ghost -> ONLY the wildcard IP -> must be dropped from resolved/live
    table = {
        "example.com": (["203.0.113.5"], None),
        "app.example.com": (["203.0.113.6"], None),
        "ghost.example.com": (["10.0.0.9"], None),   # wildcard-only
    }
    res = _run_pipeline(monkeypatch, names=["app.example.com", "ghost.example.com"],
                        table=table, wildcard=True, probe_live=["example.com", "app.example.com"])
    assert "10.0.0.9" in res.wildcard_ips
    assert "ghost.example.com" not in res.resolved            # never promoted
    assert res.records["ghost.example.com"].classification == RESOLVES_DEAD
    assert "ghost.example.com" not in res.live_hosts          # never scanned


def test_nxdomain_names_are_not_resolved(monkeypatch):
    table = {"example.com": (["203.0.113.5"], None), "app.example.com": (["203.0.113.6"], None)}
    res = _run_pipeline(monkeypatch, names=["app.example.com", "dead.example.com"],
                        table=table, wildcard=False, probe_live=["app.example.com"])
    assert res.records["dead.example.com"].classification == NXDOMAIN
    assert "dead.example.com" not in res.resolved
    assert "dead.example.com" not in res.live_hosts


def test_cname_only_wildcard_name_is_kept(monkeypatch):
    # a name with a CNAME is a real distinct record even if its A is in the wildcard set
    table = {
        "example.com": (["203.0.113.5"], None),
        "svc.example.com": (["10.0.0.9"], "target.herokudns.com"),  # wildcard IP BUT has CNAME
    }
    res = _run_pipeline(monkeypatch, names=["svc.example.com"], table=table,
                        wildcard=True, probe_live=["svc.example.com"])
    assert "svc.example.com" in res.resolved


# ── to_scope_list() ──────────────────────────────────────────────────────────


def test_to_scope_list_excludes_dead_includes_apex(monkeypatch):
    table = {
        "example.com": (["203.0.113.5"], None),
        "app.example.com": (["203.0.113.6"], None),
        "api.example.com": (["203.0.113.7"], None),
        "dead.example.com": (["203.0.113.8"], None),   # resolves but probe says dead
    }
    res = _run_pipeline(monkeypatch, names=["app.example.com", "api.example.com", "dead.example.com"],
                        table=table, wildcard=False,
                        probe_live=["app.example.com", "api.example.com"])  # dead not live
    scope = res.to_scope_list()
    hosts = set(scope.split(","))
    assert "example.com" in hosts                       # apex/target always present
    assert "app.example.com" in hosts and "api.example.com" in hosts
    assert "dead.example.com" not in hosts              # dead host excluded


def test_to_scope_list_apex_present_even_if_apex_not_live():
    r = DiscoveryResult(domain=DOMAIN)
    r.live_hosts = ["app.example.com", "evil.other.net"]  # off-scope live host must be filtered
    r.records = {
        "app.example.com": HostRecord("app.example.com", classification=LIVE),
        "evil.other.net": HostRecord("evil.other.net", classification=LIVE),
    }
    scope = set(r.to_scope_list().split(","))
    assert scope == {"example.com", "app.example.com"}  # apex + in-scope live only


# ── graceful skip of absent binaries ─────────────────────────────────────────


def test_subfinder_skips_when_binary_absent(monkeypatch):
    monkeypatch.setattr(disco.shutil, "which", lambda name: None)
    assert disco._source_subfinder(DOMAIN, timeout=1) == []


def test_amass_skips_when_binary_absent(monkeypatch):
    monkeypatch.setattr(disco.shutil, "which", lambda name: None)
    assert disco._source_amass(DOMAIN, timeout=1) == []


def test_subfinder_runs_when_present(monkeypatch):
    monkeypatch.setattr(disco.shutil, "which", lambda name: "/usr/bin/subfinder")
    monkeypatch.setattr(disco, "_run_tool_lines",
                        lambda argv, *, timeout: ["a.example.com", "b.example.com"])
    assert disco._source_subfinder(DOMAIN, timeout=1) == ["a.example.com", "b.example.com"]


# ── CLI smoke test (everything mocked, no network) ───────────────────────────


def test_cli_discover_smoke(monkeypatch, tmp_path):
    from d4st import cli

    fake = DiscoveryResult(domain=DOMAIN)
    fake.all_names = ["example.com", "app.example.com", "dead.example.com"]
    fake.sources_used = ["crtsh"]
    fake.resolved = {"app.example.com": {"ips": ["203.0.113.6"], "cname": None}}
    fake.live_hosts = ["app.example.com"]
    fake.records = {
        "app.example.com": HostRecord("app.example.com", ips=["203.0.113.6"], resolved=True,
                                      classification=LIVE,
                                      probes=[{"scheme": "https", "url": "https://app.example.com/",
                                               "status": 200, "final_url": "https://app.example.com/",
                                               "server": "nginx", "title": "Home",
                                               "classification": LIVE}]),
        "dead.example.com": HostRecord("dead.example.com", classification=NXDOMAIN),
    }

    called = {}

    def fake_discover(domain, *, deep=False, resolvers=None, timeout=15, probe=True):
        called["args"] = (domain, deep, resolvers, probe)
        return fake

    monkeypatch.setattr("d4st.discovery.discover_subdomains", fake_discover)

    out_json = tmp_path / "disco.json"
    runner = CliRunner()
    result = runner.invoke(cli.main, ["discover", DOMAIN, "--json", str(out_json)])
    assert result.exit_code == 0, result.output
    assert "app.example.com" in result.output
    assert "LIVE" in result.output
    assert called["args"][0] == DOMAIN
    # JSON written and well-formed, carrying the apex+live scope
    data = json.loads(out_json.read_text())
    assert data["domain"] == DOMAIN
    assert data["live_hosts"] == ["app.example.com"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
