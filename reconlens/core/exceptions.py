# reconlens/core/exceptions.py
"""
Custom exceptions for ReconLens.

All custom exceptions inherit from ReconLensError for easy catching.
"""

from __future__ import annotations


class ReconLensError(Exception):
    """Base exception for all ReconLens errors."""
    pass


class ConfigError(ReconLensError):
    """Configuration-related errors."""
    pass


class StorageError(ReconLensError):
    """Storage/IO-related errors."""
    pass


class AnalyzerError(ReconLensError):
    """Analyzer-related errors."""
    pass


class AnalyzerNotFoundError(AnalyzerError):
    """Requested analyzer does not exist."""
    def __init__(self, name: str):
        self.name = name
        super().__init__(f"Analyzer not found: {name}")


class ProbeError(ReconLensError):
    """Probing-related errors."""
    pass


class ScopeError(ReconLensError):
    """Scope/target-related errors."""
    pass


class TargetNotFoundError(ScopeError):
    """Requested target/scope does not exist."""
    def __init__(self, scope: str):
        self.scope = scope
        super().__init__(f"Target not found: {scope}")
