"""Tool-adapter interface + registry.

Every scanner is an adapter implementing `run(ctx) -> AdapterResult`. Adapters declare
which stage they belong to (recon / crawl / scan / tls), whether they DISCOVER surface
(feed the frontier) and/or DETECT findings, and whether they emit ACTIVE attack traffic
(gated behind per-target authorization, see the plan's policy flag).

An adapter must never raise for a missing binary or a target error: it returns an
AdapterResult with ok=False and a note, so one tool failing never sinks the workflow.
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class RunContext:
    """Everything an adapter needs for one invocation."""
    target: str
    session: dict | None = None          # captured auth session (Phase 1); None = unauth
    seed_urls: list[str] = field(default_factory=list)  # frontier snapshot to scan
    workdir: str = "."
    options: dict = field(default_factory=dict)
    dry_run: bool = False


@dataclass
class AdapterResult:
    tool: str
    ok: bool
    discovered_urls: list[str] = field(default_factory=list)  # surface for the frontier
    findings: list[dict] = field(default_factory=list)        # raw native findings
    command: str = ""
    note: str = ""
    raw: object = None                                        # native JSON, kept verbatim


class ToolAdapter(ABC):
    name: str = "base"
    stage: str = "scan"          # recon | crawl | scan | tls
    discovers: bool = False      # feeds the frontier
    detects: bool = False        # produces findings
    active: bool = False         # emits attack traffic (authorization-gated)
    binary: str | None = None    # CLI binary to check for

    def available(self) -> bool:
        if self.binary is None:
            return True
        return shutil.which(self.binary) is not None

    @abstractmethod
    def run(self, ctx: RunContext) -> AdapterResult:
        ...

    # Small helper so adapters share one subprocess convention.
    def _exec(self, args: list[str], timeout: int = 900, stdin: str | None = None):
        proc = subprocess.run(
            args,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc


# ----- registry -----------------------------------------------------------------

REGISTRY: dict[str, ToolAdapter] = {}


def register(adapter_cls: type[ToolAdapter]) -> type[ToolAdapter]:
    inst = adapter_cls()
    REGISTRY[inst.name] = inst
    return adapter_cls


def get_adapter(name: str) -> ToolAdapter:
    if name not in REGISTRY:
        raise KeyError(f"unknown tool adapter: {name!r} (known: {sorted(REGISTRY)})")
    return REGISTRY[name]
