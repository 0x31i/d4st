"""Ground-truth oracle: the known-vulnerable (category, endpoint, param) points a benchmark
target exposes. Recall is measured against this. Oracles are YAML; DVWA is bundled.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from importlib import resources
from urllib.parse import urlsplit


def path_of(url_or_path: str) -> str:
    """Reduce a URL (or path) to its path component, trailing-slash-normalized."""
    if not url_or_path:
        return ""
    p = urlsplit(url_or_path).path if "//" in url_or_path else url_or_path.split("?")[0]
    p = p or "/"
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1]
    return p.lower()


@dataclass(frozen=True)
class OracleItem:
    id: str
    category: str
    endpoint: str                 # path, e.g. /vulnerabilities/sqli
    param: str | None = None
    note: str = ""

    @property
    def endpoint_path(self) -> str:
        return path_of(self.endpoint)


@dataclass
class Oracle:
    name: str
    items: list[OracleItem] = field(default_factory=list)

    def categories(self) -> list[str]:
        # preserve first-seen order
        seen: list[str] = []
        for it in self.items:
            if it.category not in seen:
                seen.append(it.category)
        return seen

    def items_in(self, category: str) -> list[OracleItem]:
        return [it for it in self.items if it.category == category]


def _from_dict(d: dict) -> Oracle:
    items = []
    for i, raw in enumerate(d.get("items", [])):
        items.append(OracleItem(
            id=raw.get("id") or f"{d.get('name', 'oracle')}-{i}",
            category=raw["category"],
            endpoint=raw["endpoint"],
            param=raw.get("param"),
            note=raw.get("note", ""),
        ))
    return Oracle(name=d.get("name", "oracle"), items=items)


def load_oracle(name_or_path: str) -> Oracle:
    import yaml
    if os.path.exists(name_or_path):
        with open(name_or_path, "r", encoding="utf-8") as fh:
            return _from_dict(yaml.safe_load(fh))
    fname = name_or_path if name_or_path.endswith(".yaml") else f"{name_or_path}.yaml"
    try:
        text = resources.files("dastng.scoring.oracles").joinpath(fname).read_text(encoding="utf-8")
        return _from_dict(yaml.safe_load(text))
    except (FileNotFoundError, ModuleNotFoundError, TypeError, AttributeError):
        pass
    fs_path = os.path.join(os.path.dirname(__file__), "oracles", fname)
    if os.path.exists(fs_path):
        with open(fs_path, "r", encoding="utf-8") as fh:
            return _from_dict(yaml.safe_load(fh))
    raise FileNotFoundError(f"oracle not found: {name_or_path!r}")
