"""Workflow loader + runner.

A workflow is a YAML file declaring ordered stages, each naming tool adapters. Discovery
adapters feed the shared frontier; detection adapters consume it. The runner loops until
the frontier converges (no new surface) or the round cap is hit.

The design borrows the declarative-YAML pattern from Osmedeus and the tool-flag conventions
from reconftw, but the runner is our own thin, dependency-light implementation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from importlib import resources

import yaml

from .adapters import get_adapter
from .adapters.base import AdapterResult, RunContext
from .frontier import Frontier


@dataclass
class WorkflowResult:
    workflow: str
    target: str
    results: list[AdapterResult] = field(default_factory=list)
    frontier_stats: dict = field(default_factory=dict)

    @property
    def findings(self) -> list[dict]:
        out: list[dict] = []
        for r in self.results:
            out.extend(r.findings)
        return out


def load_workflow(name_or_path: str) -> dict:
    """Load a workflow by bundled name (e.g. 'core') or by filesystem path."""
    if os.path.exists(name_or_path):
        with open(name_or_path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    fname = name_or_path if name_or_path.endswith(".yaml") else f"{name_or_path}.yaml"
    # Prefer packaged resources; fall back to the filesystem next to this module (robust
    # across Python 3.9 namespace-package quirks and editable installs).
    try:
        text = resources.files("d4st.workflows").joinpath(fname).read_text(encoding="utf-8")
        return yaml.safe_load(text)
    except (FileNotFoundError, ModuleNotFoundError, TypeError, AttributeError):
        pass
    fs_path = os.path.join(os.path.dirname(__file__), os.pardir, "workflows", fname)
    if os.path.exists(fs_path):
        with open(fs_path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    raise FileNotFoundError(f"workflow not found: {name_or_path!r}")


class WorkflowRunner:
    def __init__(self, spec: dict, *, allow_active: bool = False, dry_run: bool = False,
                 workdir: str = ".", log=None):
        self.spec = spec
        self.allow_active = allow_active
        self.dry_run = dry_run
        self.workdir = workdir
        self.log = log or (lambda msg: None)

    def run(self, target: str, session: dict | None = None) -> WorkflowResult:
        max_rounds = int(self.spec.get("max_rounds", 3))
        frontier = Frontier(max_rounds=max_rounds)
        frontier.add_url(target)

        stages = self.spec.get("stages", [])
        discovery_stages = [s for s in stages if s.get("kind") == "discovery"]
        detect_stages = [s for s in stages if s.get("kind") != "discovery"]

        wf = WorkflowResult(workflow=self.spec.get("name", "workflow"), target=target)

        # Convergence loop: (re)discover -> scan, until the frontier stops growing.
        while True:
            rnd = frontier.begin_round()
            self.log(f"round {rnd}: frontier {frontier.stats()['urls']} urls")

            for stage in discovery_stages:
                for tool in stage.get("tools", []):
                    res = self._run_tool(tool, target, session, frontier.urls())
                    wf.results.append(res)
                    frontier.add_urls(res.discovered_urls)

            if not frontier.should_continue():
                break

        # Detection stages run once over the converged frontier.
        for stage in detect_stages:
            for tool in stage.get("tools", []):
                res = self._run_tool(tool, target, session, frontier.urls())
                wf.results.append(res)

        wf.frontier_stats = frontier.stats()
        for cap in wf.frontier_stats.get("caps", []):
            self.log(f"COVERAGE CAP: {cap}")
        return wf

    def _run_tool(self, name: str, target: str, session, seed_urls) -> AdapterResult:
        adapter = get_adapter(name)
        if adapter.active and not self.allow_active and not self.dry_run:
            return AdapterResult(
                tool=name, ok=False,
                note="skipped: active scan not authorized for this target (pass allow_active)",
            )
        ctx = RunContext(
            target=target, session=session, seed_urls=list(seed_urls),
            workdir=self.workdir, dry_run=self.dry_run,
            options=self.spec.get("options", {}),
        )
        res = adapter.run(ctx)
        self.log(f"  {name}: {'ok' if res.ok else 'skip/err'} - {res.note}")
        return res
