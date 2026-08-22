"""Tests for PII/PHI disclosure detection. Deterministic units (mask, Luhn) + scan_text
behaviour that holds in BOTH backends (Presidio or built-in fallback)."""

from __future__ import annotations

from dastng.pii import PiiScanner, _luhn, _mask


def test_mask_never_leaks_raw_value():
    assert _mask("123-45-6789") == "*******6789"
    assert _mask("4111111111111111").endswith("1111")
    assert _mask("4111111111111111").count("*") >= 8
    # email keeps 1 char + domain, not the local part
    assert _mask("patient.name@hospital.org") == "p***@hospital.org"


def test_luhn_validates_cards():
    assert _luhn("4111111111111111") is True      # valid Visa test number
    assert _luhn("1234567890123456") is False     # fails Luhn
    assert _luhn("42") is False                    # too short


def test_scan_detects_email_and_masks():
    s = PiiScanner()
    hits = s.scan_text("reach us at admin@example.com", "http://x/p")
    emails = [h for h in hits if h.entity == "EMAIL_ADDRESS"]
    assert emails, "email not detected"
    assert "admin" not in emails[0].masked          # raw local part not stored
    assert emails[0].masked.endswith("@example.com")


def test_scan_rejects_non_luhn_card():
    s = PiiScanner()
    hits = s.scan_text("card 1234567890123456", "http://x")
    assert not [h for h in hits if h.entity == "CREDIT_CARD"], "non-Luhn card should be dropped"


def test_scan_accepts_valid_card():
    s = PiiScanner()
    hits = s.scan_text("card 4111111111111111 on file", "http://x")
    assert [h for h in hits if h.entity == "CREDIT_CARD"], "valid card not detected"


def test_backend_reports_itself():
    assert PiiScanner().backend in ("presidio", "builtin-fallback")
