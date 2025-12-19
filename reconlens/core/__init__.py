# reconlens/core/__init__.py
"""
Core utilities - pure functions with no side effects.

This module contains:
- types: Dataclasses and type definitions
- url: URL parsing utilities
- scope: Scope checking utilities
- exceptions: Custom exceptions
"""

from reconlens.core.types import (
    ParsedURL,
    AnalysisResult,
    ProbeResult,
    Target,
    RiskLevel,
)
from reconlens.core.url import parse_url, is_static_asset
from reconlens.core.scope import is_in_scope

__all__ = [
    # Types
    "ParsedURL",
    "AnalysisResult", 
    "ProbeResult",
    "Target",
    "RiskLevel",
    # URL utilities
    "parse_url",
    "is_static_asset",
    # Scope utilities
    "is_in_scope",
]
