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


def test_structured_profile_drops_ner_names():
    from dastng.pii import PiiScanner
    html = '<a title="John Smith">x</a> SSN 456-78-9012 admin@x.org'
    ents = {h.entity for h in PiiScanner(structured_only=True).scan_text(html)}
    assert "PERSON" not in ents            # NER excluded in the response-pipeline profile
    assert "US_SSN" in ents and "EMAIL_ADDRESS" in ents


def test_response_collector_dedups_by_body():
    from dastng.pii import ResponsePiiCollector
    c = ResponsePiiCollector()
    body = "card 4111111111111111, ssn 456-78-9012"
    c.feed("http://x/a", body)
    c.feed("http://x/a", body)          # identical body -> not re-scanned
    assert c._scanned == 1
    assert {h.entity for h in c.hits()} == {"CREDIT_CARD", "US_SSN"}


def test_engagement_feed_hook_collects():
    from dastng import engagement as e
    from dastng.pii import ResponsePiiCollector
    col = ResponsePiiCollector()
    e.set_pii_sink(col)
    e._feed("http://x/audit", "leaked admin@x.org and 456-78-9012")
    e.set_pii_sink(None)
    assert {h.entity for h in col.hits()} == {"EMAIL_ADDRESS", "US_SSN"}
    e._feed("http://x/after", "should-not-collect@x.org")   # sink cleared -> no-op
    assert not any("after" in h.url for h in col.hits())
