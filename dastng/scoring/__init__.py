"""Scoring harness: normalize each tool's native output + a Burp report to a canonical
(category, endpoint, param) shape, score recall/precision against a known-vuln oracle
(DVWA, WAVSEP), and build a category x tool coverage matrix with a delta-vs-Burp column.

Tool-agnostic and offline: it consumes saved native outputs, so it runs without the live
scanners or targets.
"""

from __future__ import annotations

from .normalize import NormFinding
from .oracle import Oracle, load_oracle
from .score import build_matrix, score_columns

__all__ = ["NormFinding", "Oracle", "build_matrix", "load_oracle", "score_columns"]
