"""Additional injection specialists: ghauri (SQLi, complements sqlmap), SSTImap (SSTI),
crlfuzz (CRLF / response splitting). All active.
"""

from __future__ import annotations

import re
import tempfile

from ._targets import candidate_urls
from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _cookie_header

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# ghauri prints sqlmap-style blocks: "Parameter: id (GET)" + "Type: ..."
_GH_PARAM = re.compile(r"Parameter:\s*(?P<param>.+?)\s*\((?P<place>\w+)\)")
_GH_URL = re.compile(r"(?:testing|target) URL[^']*'(?P<url>\S+?)'", re.IGNORECASE)


def parse_ghauri(text: str) -> list[dict]:
    text = _ANSI.sub("", text or "")
    if "vulnerable" not in text.lower() and "Parameter:" not in text:
        return []
    out: list[dict] = []
    for m in _GH_PARAM.finditer(text):
        out.append({"tool": "ghauri", "param": m.group("param"),
                    "place": m.group("place"), "category": "sql-injection"})
    return out


def parse_sstimap(text: str) -> list[dict]:
    text = _ANSI.sub("", text or "")
    out: list[dict] = []
    # SSTImap: "SSTImap identified the following injection point" / "Engine: Twig" etc.
    if re.search(r"template injection|injection point|Engine:\s*\w+", text, re.IGNORECASE):
        m = re.search(r"Engine:\s*(?P<engine>\w+)", text)
        out.append({"tool": "sstimap", "category": "ssti",
                    "engine": m.group("engine") if m else ""})
    return out


def parse_crlfuzz(text: str) -> list[dict]:
    text = _ANSI.sub("", text or "")
    out: list[dict] = []
    for m in re.finditer(r"\[(?:VULN|vulnerable)\]\s*(?P<url>\S+)", text, re.IGNORECASE):
        out.append({"tool": "crlfuzz", "url": m.group("url"), "category": "other"})
    return out


@register
class GhauriAdapter(ToolAdapter):
    name = "ghauri"
    stage = "scan"
    discovers = False
    detects = True
    active = True
    binary = "ghauri"

    def run(self, ctx: RunContext) -> AdapterResult:
        targets = candidate_urls(ctx.seed_urls or [ctx.target], require_params=True,
                                 cap=ctx.options.get("inject_cap", 0))
        if not targets:
            return AdapterResult(tool=self.name, ok=True, note="no parameterized URLs")
        cmd = f"ghauri -u <{len(targets)}> --batch"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd,
                                 note=f"dry-run over {len(targets)}")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="ghauri not found")
        cookie = _cookie_header(ctx.session, ctx.target)
        findings: list[dict] = []
        for url in targets:
            args = ["ghauri", "-u", url, "--batch"]
            if cookie:
                args += ["--cookie", cookie]
            try:
                proc = self._exec(args, timeout=ctx.options.get("timeout", 900))
                findings.extend(parse_ghauri(proc.stdout))
            except Exception:  # noqa: BLE001, S112
                continue
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{len(findings)} injection point(s)")


@register
class SstimapAdapter(ToolAdapter):
    name = "sstimap"
    stage = "scan"
    discovers = False
    detects = True
    active = True
    binary = "sstimap"

    def run(self, ctx: RunContext) -> AdapterResult:
        targets = candidate_urls(ctx.seed_urls or [ctx.target], require_params=True,
                                 cap=ctx.options.get("inject_cap", 0))
        if not targets:
            return AdapterResult(tool=self.name, ok=True, note="no parameterized URLs")
        cmd = f"sstimap -u <{len(targets)}>"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd,
                                 note=f"dry-run over {len(targets)}")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="sstimap not found")
        cookie = _cookie_header(ctx.session, ctx.target)
        findings: list[dict] = []
        for url in targets:
            args = ["sstimap", "-u", url]
            if cookie:
                args += ["--cookie", cookie]
            try:
                proc = self._exec(args, timeout=ctx.options.get("timeout", 600))
                findings.extend(parse_sstimap(proc.stdout))
            except Exception:  # noqa: BLE001, S112
                continue
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{len(findings)} ssti")


@register
class CrlfuzzAdapter(ToolAdapter):
    name = "crlfuzz"
    stage = "scan"
    discovers = False
    detects = True
    active = True
    binary = "crlfuzz"

    def run(self, ctx: RunContext) -> AdapterResult:
        targets = candidate_urls(ctx.seed_urls or [ctx.target], require_params=False, cap=0)
        cmd = f"crlfuzz -l <{len(targets)}>"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note="crlfuzz not found")
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
                fh.write("\n".join(targets))
                list_path = fh.name
            # Throttle: crlfuzz defaults to 25 concurrency; honor the scan politeness so CRLF
            # fuzzing doesn't DoS a fragile target.
            _cargs = ["crlfuzz", "-l", list_path, "-s",
                      "-c", str(ctx.options.get("workers", 25))]
            proc = self._exec(_cargs, timeout=ctx.options.get("timeout", 600))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")
        findings = parse_crlfuzz(proc.stdout)
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{len(findings)} crlf")
