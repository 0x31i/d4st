"""Parse a Burp Suite XML export into canonical NormFindings (the reference column).

Burp Pro: Target -> right-click -> Report issues -> XML. Each <issue> has <type>, <name>,
<host>, <path>, <severity>. Param is not reliably in a field, so it is left None (the scorer
matches leniently on category + endpoint).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from . import categories as C
from .normalize import NormFinding
from .oracle import path_of


def _text(el, tag: str) -> str:
    child = el.find(tag)
    return (child.text or "").strip() if child is not None and child.text else ""


def parse_burp(xml_text: str) -> list[NormFinding]:
    if not (xml_text or "").strip():
        return []
    root = ET.fromstring(xml_text)
    issues = root.findall(".//issue")
    out: list[NormFinding] = []
    for issue in issues:
        name = _text(issue, "name")
        path = _text(issue, "path") or _text(issue, "location")
        severity = _text(issue, "severity")
        cat = C.classify([], name, default=C.OTHER)
        out.append(NormFinding(
            tool="burp", category=cat, endpoint=path_of(path) or None,
            param=None, severity=severity, url=path,
            raw={"name": name, "type": _text(issue, "type")},
        ))
    return out
