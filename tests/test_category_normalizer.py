"""ZAP/Burp passive alert names must normalize to real categories, not the OTHER bucket.

Regression: config/info/dependency alerts (Application Error Disclosure, Content-Type Header
Missing, CORS, Cacheable response, Vulnerable JS Library, ...) were all collapsing to 'other',
which hid d4st<->Burp parity and inflated the diff's Burp-only count."""
import pytest

from d4st.scoring import categories as C


@pytest.mark.parametrize("name,expected", [
    # information disclosure
    ("Application Error Disclosure", C.INFO_DISCLOSURE),
    ("Information Disclosure - Sensitive Information in URL", C.INFO_DISCLOSURE),
    ("Information Disclosure - Debug Error Messages", C.INFO_DISCLOSURE),
    ("Email addresses disclosed", C.INFO_DISCLOSURE),
    ("Directory Browsing", C.INFO_DISCLOSURE),
    # misconfiguration / header & transport & cookie hygiene
    ("Content-Type Header Missing", C.MISCONFIGURATION),
    ("X-Content-Type-Options Header Missing", C.MISCONFIGURATION),
    ("Strict-Transport-Security Header Not Set", C.MISCONFIGURATION),
    ("Content Security Policy (CSP) Header Not Set", C.MISCONFIGURATION),
    ("Re-examine Cache-control Directives", C.MISCONFIGURATION),
    ("Cacheable HTTPS response", C.MISCONFIGURATION),
    ("Cross-origin resource sharing", C.MISCONFIGURATION),
    ("Frameable response (potential Clickjacking)", C.MISCONFIGURATION),
    ("Cross-domain script include", C.MISCONFIGURATION),
    ("Cookie No HttpOnly Flag", C.MISCONFIGURATION),
    # dependency
    ("Vulnerable JavaScript Library", C.VULN_JS_DEPENDENCY),
    ("jQuery known vulnerabilities (retire.js)", C.VULN_JS_DEPENDENCY),
])
def test_passive_alert_names_classify(name, expected):
    assert C.classify([], name) == expected


@pytest.mark.parametrize("cwe,expected", [
    ("CWE-209", C.INFO_DISCLOSURE),
    ("CWE-345", C.MISCONFIGURATION),
    ("CWE-1021", C.MISCONFIGURATION),
    ("CWE-1104", C.VULN_JS_DEPENDENCY),
])
def test_cwe_ids_classify(cwe, expected):
    assert C.classify([cwe], "") == expected


def test_injection_still_wins_over_config_keywords():
    # an injection alert must not be mis-bucketed by the new broad config patterns
    assert C.classify([], "SQL Injection") == C.SQL_INJECTION
    assert C.classify([], "Cross Site Scripting (Reflected)") == C.XSS
