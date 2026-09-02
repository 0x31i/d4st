from d4st.orchestrator.adapters import REGISTRY
from d4st.orchestrator.adapters.api import parse_graphw00f, parse_jwt_tool
from d4st.orchestrator.adapters.discovery import parse_feroxbuster, parse_gau, parse_x8
from d4st.orchestrator.adapters.injection2 import (
    parse_crlfuzz,
    parse_ghauri,
    parse_sstimap,
)
from d4st.orchestrator.adapters.secrets import (
    parse_gitleaks,
    parse_semgrep,
    parse_trufflehog,
)


def test_full_roster_registered():
    expected = {
        "katana", "nuclei", "zap", "sqlmap", "dalfox", "commix",  # core
        "feroxbuster", "gau", "x8",                                # discovery
        "ghauri", "sstimap", "crlfuzz",                            # injection2
        "gitleaks", "trufflehog", "semgrep",                      # secrets
        "jwt_tool", "graphw00f", "schemathesis",                  # api
    }
    assert expected <= set(REGISTRY), f"missing: {expected - set(REGISTRY)}"


def test_active_flags():
    # recon/discovery/static = passive; injection/fuzzing = active
    for n in ("feroxbuster", "gau", "x8", "gitleaks", "trufflehog", "semgrep", "graphw00f"):
        assert REGISTRY[n].active is False, n
    for n in ("ghauri", "sstimap", "crlfuzz", "jwt_tool", "schemathesis"):
        assert REGISTRY[n].active is True, n


def test_parse_feroxbuster():
    s = ('{"type":"response","url":"http://h/a","status":200}\n'
         '{"type":"response","url":"http://h/b","status":404}\n'
         '{"type":"statistics"}')
    assert parse_feroxbuster(s) == ["http://h/a"]


def test_parse_gau():
    assert parse_gau("http://h/a\nhttp://h/b\n# note\n") == ["http://h/a", "http://h/b"]


def test_parse_x8():
    s = '[{"url":"http://h/a","found_params":[{"name":"debug"},{"name":"admin"}]}]'
    out = parse_x8(s)
    assert {p["param"] for p in out} == {"debug", "admin"}


def test_parse_ghauri():
    s = "Parameter: id (GET)\n    Type: boolean-based blind\nid is vulnerable"
    out = parse_ghauri(s)
    assert out and out[0]["category"] == "sql-injection" and out[0]["param"] == "id"


def test_parse_sstimap():
    assert parse_sstimap("SSTImap ... Engine: Twig ... template injection")[0]["engine"] == "Twig"
    assert parse_sstimap("nothing here") == []


def test_parse_crlfuzz():
    assert parse_crlfuzz("[VULN] http://h/a?x=1")[0]["url"] == "http://h/a?x=1"


def test_parse_gitleaks():
    s = '[{"RuleID":"aws-key","File":"app.js"}]'
    out = parse_gitleaks(s)
    assert out[0]["category"] == "info-disclosure" and out[0]["rule"] == "aws-key"


def test_parse_trufflehog():
    s = '{"DetectorName":"AWS","Verified":true,"Raw":"AKIA..."}'
    assert parse_trufflehog(s)[0]["detector"] == "AWS"


def test_parse_semgrep():
    s = '{"results":[{"check_id":"js.xss.dom","path":"a.js"}]}'
    assert parse_semgrep(s)[0]["category"] == "xss"


def test_parse_jwt_tool():
    assert parse_jwt_tool("[+] alg:none accepted VULNERABLE")[0]["issue"].lower().startswith("alg")


def test_parse_graphw00f():
    assert parse_graphw00f("Discovered GraphQL Engine: (Apollo)")[0]["engine"] == "Apollo"
    assert parse_graphw00f("no gql") == []
