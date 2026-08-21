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
XXE = "xxe"
SSTI = "ssti"
INFO_DISCLOSURE = "info-disclosure"
MISCONFIGURATION = "misconfiguration"
OTHER = "other"

CANONICAL = {
    SQL_INJECTION, XSS, COMMAND_INJECTION, FILE_INCLUSION, FILE_UPLOAD, CSRF,
    OPEN_REDIRECT, WEAK_SESSION, SSRF, XXE, SSTI, INFO_DISCLOSURE, MISCONFIGURATION, OTHER,
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
    "1336": SSTI, "94": SSTI,
    "200": INFO_DISCLOSURE,
    "16": MISCONFIGURATION, "693": MISCONFIGURATION,
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
    (r"template\s*injection|(?<![a-z])ssti(?![a-z])", SSTI),
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
