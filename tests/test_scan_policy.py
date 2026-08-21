"""Tests for the ScanPolicy safety flag: production-safe must actually constrain the scan."""

from __future__ import annotations

from dastng.safety import get_policy, is_state_changing


def test_state_changing_detection():
    assert is_state_changing("http://x/user/delete?id=1")
    assert is_state_changing("http://x/api/sendEmail")
    assert is_state_changing("http://x/account/transfer")
    assert is_state_changing("http://x/orders/checkout")
    # benign / injectable-but-safe endpoints must NOT be flagged
    assert not is_state_changing("http://x/products/search?q=1")
    assert not is_state_changing("http://x/profile/view?id=1")
    assert not is_state_changing("http://x/article?page=2")


def test_production_safe_is_locked_down():
    p = get_policy("production-safe")
    assert p.active_scan is True          # still scans...
    assert p.fuzz_forms is False          # ...but never mutates via forms
    assert p.skip_state_changing is True
    assert p.sqlmap_risk == 1             # no OR-based data mutation
    assert p.sqlmap_technique == "BEU"    # no time-based hang, no stacked queries
    assert p.oast_selfhosted_only is True
    assert p.politeness.rps <= 2.0        # throttled


def test_passive_only_sends_no_attack_traffic():
    p = get_policy("passive-only")
    assert p.active_scan is False
    assert p.fuzz_forms is False


def test_staging_and_aggressive_are_full_depth():
    for name in ("staging", "aggressive"):
        p = get_policy(name)
        assert p.active_scan is True
        assert p.fuzz_forms is True
        assert p.sqlmap_risk >= 2


def test_legacy_aliases_resolve():
    assert get_policy("polite").name == "production-safe"
    assert get_policy("normal").name == "staging"
    assert get_policy("unknown-name").name == "staging"   # safe default


def test_sqlmap_args_render():
    assert get_policy("production-safe").sqlmap_args() == \
        ["--level", "2", "--risk", "1", "--technique=BEU"]
