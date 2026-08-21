"""Match normalized findings against the oracle and build the coverage matrix.

Recall is the headline metric on DVWA (which oracle points each column detected). Precision is
reported best-effort with a caveat: DVWA carries many real issues beyond the oracle, so a
finding that misses the oracle is not necessarily a false positive. WAVSEP (Phase 4), with its
designated FP cases, is the clean precision benchmark.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .normalize import NormFinding
from .oracle import Oracle, OracleItem, path_of


def _endpoint_match(finding_ep: str | None, oracle_ep: str) -> bool:
    if not oracle_ep:
        return True
    if not finding_ep:
        return True  # lenient: unknown endpoint does not veto a category+param match
    a, b = path_of(finding_ep), path_of(oracle_ep)
    # segment-aware: exact, or one is a path-segment prefix of the other (so /sqli does NOT
    # match /sqli_blind, but /fi matches /fi/index.php).
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def _param_match(finding_param: str | None, oracle_param: str | None) -> bool:
    if not oracle_param or not finding_param:
        return True
    return oracle_param.lower() == finding_param.lower()


def matches(f: NormFinding, item: OracleItem) -> bool:
    return (f.category == item.category
            and _endpoint_match(f.endpoint, item.endpoint_path)
            and _param_match(f.param, item.param))


@dataclass
class ColumnScore:
    name: str
    detected: set = field(default_factory=set)     # oracle item ids detected
    matched_findings: int = 0
    total_findings: int = 0

    def recall_in(self, oracle: Oracle, category: str) -> tuple[int, int]:
        items = oracle.items_in(category)
        tp = sum(1 for it in items if it.id in self.detected)
        return tp, len(items)

    @property
    def precision(self) -> float | None:
        if self.total_findings == 0:
            return None
        return self.matched_findings / self.total_findings


def score_column(name: str, findings: list[NormFinding], oracle: Oracle) -> ColumnScore:
    col = ColumnScore(name=name, total_findings=len(findings))
    for f in findings:
        hit = False
        for it in oracle.items:
            if matches(f, it):
                col.detected.add(it.id)
                hit = True
        if hit:
            col.matched_findings += 1
    return col


def score_columns(oracle: Oracle, columns: dict[str, list[NormFinding]]) -> dict[str, ColumnScore]:
    """columns: {column_name: findings}. Adds a synthetic 'pipeline' union of all non-burp,
    non-pipeline columns."""
    scored = {name: score_column(name, fs, oracle) for name, fs in columns.items()}
    union: list[NormFinding] = []
    for name, fs in columns.items():
        if name in ("burp", "pipeline"):
            continue
        union.extend(fs)
    scored["pipeline"] = score_column("pipeline", union, oracle)
    return scored


@dataclass
class MatrixRow:
    category: str
    total: int
    recalls: dict = field(default_factory=dict)   # column -> (tp, total)
    delta: float | None = None                    # pipeline_recall - burp_recall


def build_matrix(oracle: Oracle, scored: dict[str, ColumnScore],
                 columns_order: list[str]) -> list[MatrixRow]:
    rows: list[MatrixRow] = []
    for cat in oracle.categories():
        total = len(oracle.items_in(cat))
        row = MatrixRow(category=cat, total=total)
        for col in columns_order:
            if col in scored:
                row.recalls[col] = scored[col].recall_in(oracle, cat)
        if "pipeline" in scored and "burp" in scored:
            p_tp, p_n = scored["pipeline"].recall_in(oracle, cat)
            b_tp, b_n = scored["burp"].recall_in(oracle, cat)
            p_r = (p_tp / p_n) if p_n else 0.0
            b_r = (b_tp / b_n) if b_n else 0.0
            row.delta = round(p_r - b_r, 3)
        rows.append(row)
    return rows


def matrix_to_dict(oracle: Oracle, scored: dict[str, ColumnScore],
                   columns_order: list[str]) -> dict:
    rows = build_matrix(oracle, scored, columns_order)
    return {
        "oracle": oracle.name,
        "columns": columns_order,
        "rows": [
            {
                "category": r.category,
                "oracle_items": r.total,
                "recall": {c: {"tp": tp, "n": n, "pct": round(tp / n, 3) if n else None}
                           for c, (tp, n) in r.recalls.items()},
                "delta_pipeline_minus_burp": r.delta,
            }
            for r in rows
        ],
        "precision": {c: scored[c].precision for c in columns_order if c in scored},
    }
