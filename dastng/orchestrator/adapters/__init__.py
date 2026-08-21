"""Tool adapters. Each adapter wraps one scanner behind a uniform interface and is
registered by name so YAML workflows can reference it.
"""

from __future__ import annotations

# Import adapter modules for their registration side effects. Add new tools here.
from . import (
    api,  # noqa: F401
    commix,  # noqa: F401
    dalfox,  # noqa: F401
    discovery,  # noqa: F401
    dotdotpwn,  # noqa: F401
    ghauri,  # noqa: F401
    injection2,  # noqa: F401
    katana,  # noqa: F401
    lfi_fuzz,  # noqa: F401
    nuclei,  # noqa: F401
    rfi_oast,  # noqa: F401
    secrets,  # noqa: F401
    sqlmap,  # noqa: F401
    zap,  # noqa: F401
)
from .base import REGISTRY, AdapterResult, ToolAdapter, get_adapter, register

__all__ = [
    "REGISTRY",
    "AdapterResult",
    "ToolAdapter",
    "get_adapter",
    "register",
]
