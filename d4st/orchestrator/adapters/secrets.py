"""Secret / client-side JS analysis: gitleaks, trufflehog, semgrep, jsluice. These scan the
app's fetched JavaScript (a directory of downloaded .js), so they need options['js_dir'].
All non-active (static). Findings are categorized info-disclosure.
"""

from __future__ import annotations

import json
import os

from .base import AdapterResult, RunContext, ToolAdapter, register

# Canonical category strings (kept in sync with d4st.scoring.categories, no import to
# avoid coupling the orchestrator to the scoring package).
_INFO_DISCLOSURE = "info-disclosure"
_XSS = "xss"


def parse_gitleaks(text: str) -> list[dict]:
    text = (text or "").strip()
    if not text:
        return []
    try:
        arr = json.loads(text)
    except json.JSONDecodeError:
        return []
    return [{"tool": "gitleaks", "rule": o.get("RuleID"), "file": o.get("File"),
             "category": _INFO_DISCLOSURE}
            for o in (arr if isinstance(arr, list) else []) if isinstance(o, dict)]


def parse_trufflehog(text: str) -> list[dict]:
    out: list[dict] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if o.get("DetectorName") or o.get("Raw"):
            out.append({"tool": "trufflehog", "detector": o.get("DetectorName"),
                        "verified": o.get("Verified"), "category": _INFO_DISCLOSURE})
    return out


def parse_semgrep(text: str) -> list[dict]:
    text = (text or "").strip()
    if not text:
        return []
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for r in obj.get("results", []):
        check = r.get("check_id", "")
        cat = _XSS if "xss" in check.lower() else _INFO_DISCLOSURE
        out.append({"tool": "semgrep", "check": check, "path": r.get("path"), "category": cat})
    return out


def _js_dir(ctx: RunContext) -> str | None:
    d = ctx.options.get("js_dir")
    return d if d and os.path.isdir(d) else None


class _DirScanner(ToolAdapter):
    stage = "scan"
    discovers = False
    detects = True
    active = False

    def _args(self, d: str) -> list[str]:
        raise NotImplementedError

    def _parse(self, stdout: str) -> list[dict]:
        raise NotImplementedError

    def run(self, ctx: RunContext) -> AdapterResult:
        cmd = f"{self.name} <js_dir>"
        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd, note="dry-run")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"{self.binary} not found")
        d = _js_dir(ctx)
        if not d:
            return AdapterResult(tool=self.name, ok=True, command=cmd,
                                 note="no js_dir provided (skipped)")
        try:
            proc = self._exec(self._args(d), timeout=ctx.options.get("timeout", 600))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")
        findings = self._parse(proc.stdout)
        return AdapterResult(tool=self.name, ok=True, findings=findings, command=cmd,
                             note=f"{len(findings)} finding(s)", raw=proc.stdout)


@register
class GitleaksAdapter(_DirScanner):
    name = "gitleaks"
    binary = "gitleaks"

    def _args(self, d):
        return ["gitleaks", "detect", "--source", d, "--no-git",
                "--report-format", "json", "--report-path", "/dev/stdout"]

    def _parse(self, stdout):
        return parse_gitleaks(stdout)


@register
class TrufflehogAdapter(_DirScanner):
    name = "trufflehog"
    binary = "trufflehog"

    def _args(self, d):
        return ["trufflehog", "filesystem", d, "--json"]

    def _parse(self, stdout):
        return parse_trufflehog(stdout)


@register
class SemgrepAdapter(_DirScanner):
    name = "semgrep"
    binary = "semgrep"

    def _args(self, d):
        return ["semgrep", "--config", "auto", "--json", d]

    def _parse(self, stdout):
        return parse_semgrep(stdout)
