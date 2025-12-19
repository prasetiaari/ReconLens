# core/exceptions.py
"""
Custom exceptions for ReconLens.

All custom exceptions inherit from ReconLensError for easy catching.
Provides structured error handling with context information.

Enterprise-grade features:
- Exception hierarchy for granular error handling
- Context information in exceptions
- Serialization support for API responses
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class ReconLensError(Exception):
    """
    Base exception for all ReconLens errors.
    
    All custom exceptions inherit from this, allowing:
    - Catch all ReconLens errors: except ReconLensError
    - Catch specific errors: except AnalyzerNotFoundError
    """
    
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        self.message = message
        self.context = context or {}
        super().__init__(message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize for API responses."""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "context": self.context,
        }


class ConfigError(ReconLensError):
    """Configuration-related errors."""
    pass


class StorageError(ReconLensError):
    """Storage/IO-related errors."""
    pass


class FileNotFoundError(StorageError):
    """Requested file does not exist."""
    def __init__(self, path: str):
        self.path = path
        super().__init__(f"File not found: {path}", {"path": path})


class AnalyzerError(ReconLensError):
    """Analyzer-related errors."""
    pass


class AnalyzerNotFoundError(AnalyzerError):
    """Requested analyzer does not exist."""
    def __init__(self, name: str):
        self.name = name
        available = []  # Will be populated by analyzer registry
        super().__init__(
            f"Analyzer not found: {name}",
            {"name": name, "available": available}
        )


class AnalyzerExecutionError(AnalyzerError):
    """Error during analyzer execution."""
    def __init__(self, analyzer_name: str, message: str):
        self.analyzer_name = analyzer_name
        super().__init__(
            f"Analyzer '{analyzer_name}' failed: {message}",
            {"analyzer_name": analyzer_name}
        )


class ProbeError(ReconLensError):
    """Probing-related errors."""
    pass


class ProbeTimeoutError(ProbeError):
    """Probe request timed out."""
    def __init__(self, url: str, timeout: float):
        self.url = url
        self.timeout = timeout
        super().__init__(
            f"Probe timeout after {timeout}s: {url}",
            {"url": url, "timeout": timeout}
        )


class ScopeError(ReconLensError):
    """Scope/target-related errors."""
    pass


class TargetNotFoundError(ScopeError):
    """Requested target/scope does not exist."""
    def __init__(self, scope: str):
        self.scope = scope
        super().__init__(
            f"Target not found: {scope}",
            {"scope": scope}
        )


class TargetExistsError(ScopeError):
    """Target already exists."""
    def __init__(self, scope: str):
        self.scope = scope
        super().__init__(
            f"Target already exists: {scope}",
            {"scope": scope}
        )


class ValidationError(ReconLensError):
    """Input validation error."""
    def __init__(self, field: str, message: str, value: Any = None):
        self.field = field
        self.value = value
        super().__init__(
            f"Validation error on '{field}': {message}",
            {"field": field, "value": str(value) if value else None}
        )


class RateLimitError(ReconLensError):
    """Rate limit exceeded."""
    def __init__(self, limit: int, window: str):
        self.limit = limit
        self.window = window
        super().__init__(
            f"Rate limit exceeded: {limit} requests per {window}",
            {"limit": limit, "window": window}
        )


class ExternalToolError(ReconLensError):
    """Error from external tool (gau, subfinder, etc.)."""
    def __init__(self, tool: str, message: str, exit_code: Optional[int] = None):
        self.tool = tool
        self.exit_code = exit_code
        super().__init__(
            f"External tool '{tool}' failed: {message}",
            {"tool": tool, "exit_code": exit_code}
        )


class AIServiceError(ReconLensError):
    """AI/LLM service error."""
    def __init__(self, provider: str, message: str):
        self.provider = provider
        super().__init__(
            f"AI service '{provider}' error: {message}",
            {"provider": provider}
        )
