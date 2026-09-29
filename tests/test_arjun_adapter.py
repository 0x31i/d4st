"""arjun parameter-discovery adapter: JSON parse + param-URL synthesis (non-active recon)."""
from d4st.orchestrator.adapters import discovery
from d4st.orchestrator.adapters.base import REGISTRY


def test_registered_and_non_active():
    assert "arjun" in REGISTRY
    a = REGISTRY["arjun"]
    assert a.stage == "recon" and a.active is False and a.discovers is True


def test_parse_arjun_dict_schema():
    obj = {"https://x/y": {"params": ["id", "debug"], "method": "GET", "headers": {}}}
    rows = discovery.parse_arjun(obj)
    assert {r["param"] for r in rows} == {"id", "debug"}
    assert all(r["url"] == "https://x/y" for r in rows)


def test_parse_arjun_empty_and_bad():
    assert discovery.parse_arjun({}) == []
    assert discovery.parse_arjun(None) == []
    assert discovery.parse_arjun("garbage") == []


def test_with_param_merges_query():
    assert discovery._with_param("https://x/a", "id") == "https://x/a?id=1"
    out = discovery._with_param("https://x/a?p=2", "id")
    assert "p=2" in out and "id=1" in out
    # existing param not clobbered
    assert discovery._with_param("https://x/a?id=9", "id") == "https://x/a?id=9"
