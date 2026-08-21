"""nuclei scan adapter (detection). Reference implementation of a DETECT adapter.

Runs nuclei over the frontier URL list. Phase 2 turns on -dast/fuzzing (-ft/-fm), wires
interactsh (OAST) for blind-vuln callbacks, and injects the auth secrets file. Nuclei's
template checks are passive-ish; the fuzzing/DAST payloads are ACTIVE (authorization-gated).
"""

from __future__ import annotations

import json
import tempfile

from .base import AdapterResult, RunContext, ToolAdapter, register
from .session_util import _session_header_args


@register
class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    stage = "scan"
    discovers = False
    detects = True
    active = True  # -dast fuzzing emits attack traffic; gate per-target authorization
    binary = "nuclei"

    def run(self, ctx: RunContext) -> AdapterResult:
        targets = ctx.seed_urls or [ctx.target]
        args = ["nuclei", "-jsonl", "-silent"]
        args += _session_header_args(ctx.session, ctx.target)
        # Phase 2: -dast -ft/-fm, -secret-file <auth>, -iserver <interactsh>.
        cmd = "nuclei -jsonl -silent -l <frontier>"

        if ctx.dry_run:
            return AdapterResult(tool=self.name, ok=True, command=cmd,
                                 note=f"dry-run over {len(targets)} target(s)")
        if not self.available():
            return AdapterResult(tool=self.name, ok=False, command=cmd,
                                 note="nuclei binary not found on PATH")

        try:
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
                fh.write("\n".join(targets))
                list_path = fh.name
            proc = self._exec(args + ["-l", list_path], timeout=ctx.options.get("timeout", 1800))
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(tool=self.name, ok=False, command=cmd, note=f"exec error: {exc}")

        findings: list[dict] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return AdapterResult(
            tool=self.name,
            ok=proc.returncode in (0, 1),  # nuclei exits 1 when findings present in some modes
            findings=findings,
            command=cmd,
            note=f"{len(findings)} finding(s)",
            raw=proc.stdout,
        )
