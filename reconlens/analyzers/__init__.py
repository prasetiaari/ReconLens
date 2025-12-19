# reconlens/analyzers/__init__.py
"""
Analyzer modules for URL classification.

Each analyzer detects specific security-relevant patterns in URLs.
All analyzers inherit from BaseAnalyzer and only need to implement
the `should_include` method.

Usage:
    from reconlens.analyzers import get_analyzer, list_analyzers
    
    analyzer = get_analyzer("open_redirect")
    result = analyzer.analyze(urls, target)
"""

from __future__ import annotations

from typing import Dict, Type, List

from reconlens.analyzers.base import BaseAnalyzer
from reconlens.core.exceptions import AnalyzerNotFoundError


# Registry of all analyzers
_REGISTRY: Dict[str, Type[BaseAnalyzer]] = {}


def register(cls: Type[BaseAnalyzer]) -> Type[BaseAnalyzer]:
    """
    Decorator to register an analyzer class.
    
    Usage:
        @register
        class MyAnalyzer(BaseAnalyzer):
            ...
    """
    instance = cls()
    _REGISTRY[instance.name] = cls
    return cls


def get_analyzer(name: str) -> BaseAnalyzer:
    """
    Get an analyzer instance by name.
    
    Args:
        name: Analyzer name (e.g., "open_redirect")
        
    Returns:
        Analyzer instance
        
    Raises:
        AnalyzerNotFoundError: If analyzer doesn't exist
    """
    if name not in _REGISTRY:
        raise AnalyzerNotFoundError(name)
    return _REGISTRY[name]()


def list_analyzers() -> List[str]:
    """
    List all registered analyzer names.
    
    Returns:
        List of analyzer names
    """
    return list(_REGISTRY.keys())


def get_all_analyzers() -> List[BaseAnalyzer]:
    """
    Get instances of all registered analyzers.
    
    Returns:
        List of analyzer instances
    """
    return [cls() for cls in _REGISTRY.values()]


# Import analyzers to trigger registration
# These imports happen AFTER registry functions are defined
from reconlens.analyzers.open_redirect import OpenRedirectAnalyzer  # noqa: E402, F401
from reconlens.analyzers.sensitive_paths import SensitivePathsAnalyzer  # noqa: E402, F401
from reconlens.analyzers.sensitive_params import SensitiveParamsAnalyzer  # noqa: E402, F401
from reconlens.analyzers.jwt import JWTAnalyzer  # noqa: E402, F401

__all__ = [
    "BaseAnalyzer",
    "register",
    "get_analyzer",
    "list_analyzers",
    "get_all_analyzers",
]
