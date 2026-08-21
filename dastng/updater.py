"""Update manager: fetch the freshest detection content once (online), stamp when each
component was updated, then scans can run offline/air-gapped.

Why: a DAST tool is only as good as its templates/rules, which change daily. But client
networks (healthcare/PHI) often forbid outbound internet from a scanning appliance. So we
decouple 'update' (reach the internet once) from 'scan' (runs from the cached content). The
manifest records each component's version + timestamp for reproducible, reportable results,
and a freshness check warns when content is stale.

Components: nuclei-templates (the big one), Semgrep registry rules (pre-warmed cache), the
retire.js vuln-JS database, and recorded tool versions.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone


def data_dir() -> str:
    d = os.environ.get("DASTNG_DATA_DIR") or os.path.join(os.path.expanduser("~"), ".dast-ng")
    os.makedirs(d, exist_ok=True)
    return d


def _manifest_path() -> str:
    return os.path.join(data_dir(), "updates.json")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _run(args: list[str], timeout: int = 600) -> tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:  # noqa: BLE001
        return 1, f"exec error: {exc}"


@dataclass
class Manifest:
    components: dict = field(default_factory=dict)   # name -> {version, updated_at, source, note}

    @classmethod
    def load(cls) -> Manifest:
        p = _manifest_path()
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                return cls(components=json.load(fh).get("components", {}))
        return cls()

    def save(self) -> None:
        with open(_manifest_path(), "w", encoding="utf-8") as fh:
            json.dump({"components": self.components, "saved_at": _now()}, fh, indent=2)

    def stamp(self, name: str, version: str = "", source: str = "", note: str = "") -> None:
        self.components[name] = {"version": version, "updated_at": _now(),
                                 "source": source, "note": note}

    def age_days(self, name: str) -> float | None:
        c = self.components.get(name)
        if not c or not c.get("updated_at"):
            return None
        try:
            then = datetime.fromisoformat(c["updated_at"])
        except ValueError:
            return None
        return (datetime.now(timezone.utc) - then).total_seconds() / 86400.0


# ----- per-component updaters (each degrades gracefully if the tool is absent) ------------

def update_nuclei_templates(m: Manifest) -> str:
    if not shutil.which("nuclei"):
        return "nuclei not installed"
    _run(["nuclei", "-update-templates", "-silent"], timeout=900)
    # read the installed templates version
    ver = ""
    vfile = os.path.join(os.path.expanduser("~"), "nuclei-templates", ".version")
    if os.path.exists(vfile):
        ver = open(vfile, encoding="utf-8").read().strip()
    m.stamp("nuclei-templates", version=ver, source="projectdiscovery")
    return f"nuclei-templates updated (v{ver or '?'})"


def update_semgrep_rules(m: Manifest, configs=None) -> str:
    if not shutil.which("semgrep"):
        return "semgrep not installed"
    configs = configs or ["p/javascript", "p/secrets"]
    # pre-warm the registry cache by fetching the rulesets against an empty dir
    empty = os.path.join(data_dir(), "_empty")
    os.makedirs(empty, exist_ok=True)
    args = ["semgrep", "--quiet", "--metrics", "off", "--timeout", "60"]
    for c in configs:
        args += ["--config", c]
    args.append(empty)
    _run(args, timeout=600)
    m.stamp("semgrep-rules", version=",".join(configs), source="semgrep-registry",
            note="cache pre-warmed in ~/.semgrep")
    return f"semgrep rules pre-warmed ({', '.join(configs)})"


def update_retirejs_db(m: Manifest) -> str:
    """Sync the real retire.js vulnerability database for richer vuln-JS detection."""
    import httpx
    url = ("https://raw.githubusercontent.com/RetireJS/retire.js/master/"
           "repository/jsrepository.json")
    try:
        r = httpx.get(url, timeout=30, follow_redirects=True)
        if r.status_code != 200:
            return f"retire.js DB fetch failed (HTTP {r.status_code})"
        path = os.path.join(data_dir(), "jsrepository.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(r.text)
        m.stamp("retirejs-db", version=str(len(r.text)), source="RetireJS", note=path)
        return f"retire.js DB synced ({len(r.text)} bytes)"
    except Exception as exc:  # noqa: BLE001
        return f"retire.js DB fetch error: {exc}"


def record_tool_versions(m: Manifest) -> str:
    versions = {}
    probes = {
        "nuclei": ["nuclei", "-version"], "katana": ["katana", "-version"],
        "sqlmap": ["sqlmap", "--version"], "dalfox": ["dalfox", "version"],
        "semgrep": ["semgrep", "--version"], "ffuf": ["ffuf", "-V"],
    }
    for name, cmd in probes.items():
        if shutil.which(cmd[0]):
            _, out = _run(cmd, timeout=30)
            versions[name] = out.strip().splitlines()[0][:60] if out.strip() else "?"
    m.stamp("tools", version=json.dumps(versions), source="local")
    return f"recorded {len(versions)} tool versions"


UPDATERS = {
    "nuclei-templates": update_nuclei_templates,
    "semgrep-rules": update_semgrep_rules,
    "retirejs-db": update_retirejs_db,
    "tools": record_tool_versions,
}


def update_all(components=None) -> tuple[Manifest, list[str]]:
    m = Manifest.load()
    names = components or list(UPDATERS)
    log = []
    for name in names:
        fn = UPDATERS.get(name)
        if fn:
            log.append(fn(m))
    m.save()
    return m, log


def freshness_report(warn_days: float = 14.0) -> list[str]:
    """Lines describing each component's age; flags stale content."""
    m = Manifest.load()
    lines = []
    for name in UPDATERS:
        age = m.age_days(name)
        if age is None:
            lines.append(f"  {name}: never updated  [run: dast-ng update]")
        else:
            tag = "  STALE" if age > warn_days else ""
            v = m.components[name].get("version", "")
            lines.append(f"  {name}: {age:.1f}d ago{(' v'+v) if v and len(v) < 20 else ''}{tag}")
    return lines


def stale_components(warn_days: float = 14.0) -> list[str]:
    m = Manifest.load()
    out = []
    for name in UPDATERS:
        age = m.age_days(name)
        if age is None or age > warn_days:
            out.append(name)
    return out
