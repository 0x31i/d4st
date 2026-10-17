"""Canonical vulnerability categories + a classifier that maps each tool's native signals
(CWE ids, alert names, template tags) onto them, so findings from different tools are
comparable.
"""

from __future__ import annotations

import re

# Canonical categories used across the oracle and all normalizers.
SQL_INJECTION = "sql-injection"
XSS = "xss"
COMMAND_INJECTION = "command-injection"
FILE_INCLUSION = "file-inclusion"
FILE_UPLOAD = "file-upload"
CSRF = "csrf"
OPEN_REDIRECT = "open-redirect"
WEAK_SESSION = "weak-session"
SSRF = "ssrf"
XPATH = "xpath"
NOSQL = "nosql-injection"
LDAP = "ldap-injection"
HPP = "parameter-pollution"
XXE = "xxe"
SSTI = "ssti"
INFO_DISCLOSURE = "info-disclosure"
MISCONFIGURATION = "misconfiguration"
VULN_JS_DEPENDENCY = "vulnerable-js-dependency"
OTHER = "other"

CANONICAL = {
    SQL_INJECTION, XSS, COMMAND_INJECTION, FILE_INCLUSION, FILE_UPLOAD, CSRF,
    OPEN_REDIRECT, WEAK_SESSION, SSRF, XXE, XPATH, NOSQL, LDAP, HPP, SSTI,
    INFO_DISCLOSURE, MISCONFIGURATION, VULN_JS_DEPENDENCY, OTHER,
}

# CWE id -> canonical category.
_CWE = {
    "89": SQL_INJECTION,
    "79": XSS,
    "78": COMMAND_INJECTION, "77": COMMAND_INJECTION,
    "98": FILE_INCLUSION, "22": FILE_INCLUSION,
    "434": FILE_UPLOAD,
    "352": CSRF,
    "601": OPEN_REDIRECT,
    "384": WEAK_SESSION, "613": WEAK_SESSION,
    "918": SSRF,
    "611": XXE,
    "643": XPATH,
    "943": NOSQL,
    "90": LDAP,
    "235": HPP,
    "1336": SSTI, "94": SSTI,
    "200": INFO_DISCLOSURE, "209": INFO_DISCLOSURE, "548": INFO_DISCLOSURE, "315": INFO_DISCLOSURE,
    "16": MISCONFIGURATION, "693": MISCONFIGURATION,
    # config/header/transport/cookie hygiene ZAP & co. commonly report (were falling to OTHER)
    "345": MISCONFIGURATION, "346": MISCONFIGURATION, "319": MISCONFIGURATION,
    "524": MISCONFIGURATION, "525": MISCONFIGURATION, "1021": MISCONFIGURATION,
    "614": MISCONFIGURATION, "1004": MISCONFIGURATION, "1275": MISCONFIGURATION,
    "1104": VULN_JS_DEPENDENCY, "937": VULN_JS_DEPENDENCY, "1395": VULN_JS_DEPENDENCY,
}

# keyword (regex) -> canonical category, checked against alert/template names + tags.
_KEYWORDS = [
    (r"sql\s*injection", SQL_INJECTION),
    (r"cross[\s-]*site\s*scripting|(?<![a-z])xss(?![a-z])", XSS),
    (r"os\s*command|command\s*injection|remote\s*code", COMMAND_INJECTION),
    ((r"remote\s*file\s*inclusion|local\s*file\s*inclusion|file\s*inclusion|"
      r"path\s*traversal|directory\s*traversal|(?<![a-z])lfi(?![a-z])|(?<![a-z])rfi(?![a-z])"),
     FILE_INCLUSION),
    (r"file\s*upload|unrestricted\s*upload", FILE_UPLOAD),
    (r"open\s*redirect", OPEN_REDIRECT),
    (r"cross[\s-]*site\s*request\s*forgery|(?<![a-z])csrf(?![a-z])", CSRF),
    (r"session\s*(id|fixation|token)|weak\s*session", WEAK_SESSION),
    (r"server[\s-]*side\s*request\s*forgery|(?<![a-z])ssrf(?![a-z])", SSRF),
    (r"xml\s*external|(?<![a-z])xxe(?![a-z])", XXE),
    (r"xpath\s*inject|(?<![a-z])xpath(?![a-z])", XPATH),
    (r"nosql\s*inject|mongo(db)?\s*inject|(?<![a-z])nosqli(?![a-z])", NOSQL),
    (r"ldap\s*inject", LDAP),
    (r"parameter\s*pollution|(?<![a-z])hpp(?![a-z])", HPP),
    (r"template\s*injection|(?<![a-z])ssti(?![a-z])", SSTI),
    (r"vulnerable\s*(javascript|js)?\s*(library|dependenc|component)|retire\.?js|"
     r"outdated\s*(javascript|js)?\s*(library|component)", VULN_JS_DEPENDENCY),
    # information disclosure (error/debug leakage, sensitive-info exposure)
    (r"error\s*disclosure|debug\s*error|application\s*error|stack\s*trace|"
     r"information\s*disclosure|sensitive\s*info(rmation)?|info(rmation)?\s*leak|"
     r"directory\s*(browsing|listing)|email\s*address(es)?\s*disclosed|"
     r"private\s*ip\s*disclosure|source\s*code\s*disclosure", INFO_DISCLOSURE),
    # config / header / transport / cookie hygiene (ZAP & Burp passive classes)
    (r"header\s*(missing|not\s*set)|content[\s-]*type\s*(header\s*)?(missing|options)|"
     r"strict[\s-]*transport[\s-]*security|(?<![a-z])hsts(?![a-z])|"
     r"x[\s-]*frame[\s-]*options|x[\s-]*content[\s-]*type[\s-]*options|"
     r"content\s*security\s*policy|(?<![a-z])csp(?![a-z])|cache[\s-]*control|cacheable|"
     r"clickjack|frameable|anti[\s-]*clickjacking|"
     r"cookie.*(httponly|secure|samesite|without)|(httponly|secure|samesite).*cookie|"
     r"cross[\s-]*origin\s*resource\s*sharing|(?<![a-z])cors(?![a-z])|"
     r"cross[\s-]*domain\s*(script\s*include|misconfiguration)", MISCONFIGURATION),
]


def _cwe_ids(cwes) -> list[str]:
    out = []
    for c in cwes or []:
        m = re.search(r"(\d+)", str(c))
        if m:
            out.append(m.group(1))
    return out


def classify(cwes=None, text: str = "", default: str = OTHER) -> str:
    """Classify using CWE ids first (most reliable), then keyword match on names/tags."""
    for cid in _cwe_ids(cwes):
        if cid in _CWE:
            return _CWE[cid]
    low = (text or "").lower()
    for pat, cat in _KEYWORDS:
        if re.search(pat, low):
            return cat
    return default
