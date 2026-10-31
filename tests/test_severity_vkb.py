"""Deterministic severity resolution (report.severity_for).

The engine's default report derives severity from a category->severity VKB. These tests pin the
verified/confidence-aware re-tiering so high-impact CONFIRMED classes surface at their true tier AT
DETECTION (no AI/review layer) while unverified leads are not inflated. See report.severity_for.
"""
from d4st.report import severity_for, VULN_META, _group_severity


def _f(category, verified=None, confidence=""):
    return {"category": category, "verified": verified, "confidence": confidence}


# --- disclosed secret / credential ---------------------------------------------------------------
def test_verified_live_secret_is_critical():
    # trufflehog Verified=true (verified=True) => proven live credential => Critical
    assert severity_for(_f("secret-disclosure", verified=True, confidence="firm")) == "critical"
    assert severity_for(_f("secret", verified=True, confidence="certain")) == "critical"


def test_firm_static_secret_match_is_high():
    # a firm/certain regex match (e.g. Azure key in JS) not proven live => High, not Critical
    assert severity_for(_f("secret-disclosure", verified=None, confidence="firm")) == "high"
    assert severity_for(_f("secret", verified=None, confidence="certain")) == "high"


def test_tentative_secret_lead_is_capped_medium():
    # a tentative / low-entropy lead must not be inflated
    assert severity_for(_f("secret-disclosure", verified=None, confidence="tentative")) == "medium"
    assert severity_for(_f("secret", verified=None, confidence="")) == "medium"


# --- unauthenticated token / SAS minting ---------------------------------------------------------
def test_verified_token_minting_is_critical():
    assert severity_for(_f("unauthenticated-token-minting", verified=True, confidence="firm")) == "critical"
    # category must exist in the VKB (was previously absent -> fell through to Info)
    assert "unauthenticated-token-minting" in VULN_META


def test_unproven_token_minting_hint_is_high():
    # verified is False is dropped upstream; a None (unproven) hint is still a High lead
    assert severity_for(_f("unauthenticated-token-minting", verified=None)) == "critical"
    assert severity_for(_f("unauthenticated-token-minting", verified=False)) == "high"


# --- authorization / access-control bypass on protected data => High -----------------------------
def test_authz_family_is_high():
    for cat in ("bola", "broken-auth", "broken-object-level-authorization",
                "broken-access-control", "idor-suspect", "mass-assignment"):
        assert severity_for(_f(cat, verified=True, confidence="certain")) == "high", cat


# --- candidates not inflated ---------------------------------------------------------------------
def test_unverified_xss_candidate_not_inflated():
    # a raw dalfox reflection candidate stays at the executable-class tier (High), never Critical
    assert severity_for(_f("xss", verified=None, confidence="tentative")) in ("high", "medium", "low")
    assert severity_for(_f("xss", verified=None, confidence="tentative")) != "critical"


def test_info_and_misc_classes_unchanged():
    assert severity_for(_f("info-disclosure")) == "low"
    assert severity_for(_f("misconfiguration")) == "medium"
    assert severity_for(_f("tls-configuration")) == "medium"
    assert severity_for(_f("open-redirect")) == "medium"
    assert severity_for(_f("pii-disclosure")) == "high"
    assert severity_for(_f("sql-injection")) == "critical"


# --- group severity = worst member ---------------------------------------------------------------
def test_group_severity_is_worst_member():
    items = [_f("secret-disclosure", verified=True, confidence="firm"),    # critical
             _f("secret-disclosure", verified=None, confidence="firm"),     # high
             _f("secret-disclosure", verified=None, confidence="tentative")]  # medium
    assert _group_severity(items) == "critical"
