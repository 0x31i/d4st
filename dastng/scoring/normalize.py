"""Normalize each tool's native output into a canonical NormFinding
(tool, category, endpoint-path, param). Reuses the Phase 2 adapter parsers.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

from ..orchestrator.adapters.commix import parse_commix
from ..orchestrator.adapters.dalfox import parse_dalfox
from ..orchestrator.adapters.zap import parse_zap
from . import categories as C
from .oracle import path_of


@dataclass
class NormFinding:
    tool: str
    category: str
    endpoint: str | None = None       # path
    param: str | None = None
    severity: str = ""
    url: str = ""
    raw: dict = field(default_factory=dict)


def _first_param(url: str) -> str | None:
    q = parse_qs(urlsplit(url).query)
    return next(iter(q), None) if q else None


# ----- nuclei -----------------------------------------------------------------

def normalize_nuclei(text: str) -> list[NormFinding]:
    out: list[NormFinding] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = o.get("info", {}) or {}
        cwes = (info.get("classification", {}) or {}).get("cwe-id", []) or []
        tags = info.get("tags", []) or []
        text_sig = " ".join([o.get("template-id", ""), info.get("name", ""),
                             " ".join(tags if isinstance(tags, list) else [str(tags)])])
        cat = C.classify(cwes, text_sig, default=C.OTHER)
        url = o.get("matched-at") or o.get("matched") or o.get("host") or ""
        out.append(NormFinding(
            tool="nuclei", category=cat, endpoint=path_of(url) or None,
            param=_first_param(url), severity=str(info.get("severity", "")),
            url=url, raw=o,
        ))
    return out


# ----- dalfox -----------------------------------------------------------------

def normalize_dalfox(text: str) -> list[NormFinding]:
    out: list[NormFinding] = []
    for o in parse_dalfox(text):
        url = o.get("data") or o.get("url") or ""
        cat = C.classify([o.get("cwe")], "xss", default=C.XSS)
        out.append(NormFinding(
            tool="dalfox", category=cat, endpoint=path_of(url) or None,
            param=o.get("param") or _first_param(url),
            severity=str(o.get("severity", "")), url=url, raw=o,
        ))
    return out


# ----- zap --------------------------------------------------------------------

def normalize_zap(report) -> list[NormFinding]:
    if isinstance(report, str):
        report = json.loads(report) if report.strip() else {}
    findings, _urls = parse_zap(report)
    out: list[NormFinding] = []
    for f in findings:
        cat = C.classify([f.get("cweid")], f.get("name", ""), default=C.OTHER)
        instances = f.get("instances") or [{}]
        for inst in instances:
            url = inst.get("uri", "")
            out.append(NormFinding(
                tool="zap", category=cat, endpoint=path_of(url) or None,
                param=inst.get("param") or _first_param(url),
                severity=f.get("severity", ""), url=url, raw=f,
            ))
    return out


# ----- sqlmap (URL-associated) ------------------------------------------------

_SM_URL = re.compile(r"testing URL '(?P<url>\S+?)'")
_SM_TARGET = re.compile(r"target URL.*?'(?P<url>\S+?)'")
_SM_PARAM = re.compile(r"^Parameter:\s*(?P<param>.+?)\s*\((?P<place>\w+)\)", re.MULTILINE)


def normalize_sqlmap(text: str) -> list[NormFinding]:
    """Associate each confirmed injection point with the nearest preceding tested URL."""
    text = text or ""
    # index of URL mentions
    url_marks = [(m.start(), m.group("url")) for m in _SM_URL.finditer(text)]
    url_marks += [(m.start(), m.group("url")) for m in _SM_TARGET.finditer(text)]
    url_marks.sort()

    def nearest_url(pos: int) -> str:
        best = ""
        for start, url in url_marks:
            if start <= pos:
                best = url
            else:
                break
        return best

    out: list[NormFinding] = []
    for m in _SM_PARAM.finditer(text):
        url = nearest_url(m.start())
        out.append(NormFinding(
            tool="sqlmap", category=C.SQL_INJECTION, endpoint=path_of(url) or None,
            param=m.group("param"), url=url,
            raw={"param": m.group("param"), "place": m.group("place")},
        ))
    return out


# ----- commix -----------------------------------------------------------------

def normalize_commix(text: str, url: str = "") -> list[NormFinding]:
    out: list[NormFinding] = []
    for o in parse_commix(text, url=url):
        u = o.get("url", url)
        out.append(NormFinding(
            tool="commix", category=C.COMMAND_INJECTION, endpoint=path_of(u) or None,
            param=o.get("param"), url=u, raw=o,
        ))
    return out


# ----- dispatch by tool name --------------------------------------------------

def normalize(tool: str, content) -> list[NormFinding]:
    tool = tool.lower()
    if tool == "nuclei":
        return normalize_nuclei(content)
    if tool == "dalfox":
        return normalize_dalfox(content)
    if tool == "zap":
        return normalize_zap(content)
    if tool == "sqlmap":
        return normalize_sqlmap(content)
    if tool == "commix":
        return normalize_commix(content)
    raise ValueError(f"no normalizer for tool {tool!r}")
