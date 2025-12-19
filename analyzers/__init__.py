# analyzers/__init__.py
"""
Analyzer modules for URL classification.

Each analyzer detects specific security-relevant patterns in URLs.
All analyzers inherit from BaseAnalyzer and only need to implement
the `should_include` method.

Enterprise-grade features:
- Registry pattern for auto-discovery
- Factory function for dependency injection
- Plugin-style architecture (add new analyzer = add new file)

Usage:
    from analyzers import get_analyzer, list_analyzers
    
    # Get specific analyzer
    analyzer = get_analyzer("open_redirect")
    result = analyzer.analyze(urls, target)
    
    # List all available
    names = list_analyzers()
    
    # Run all analyzers
    for analyzer in get_all_analyzers():
        result = analyzer.analyze(urls, target)
"""

from __future__ import annotations

from typing import Dict, Type, List, Optional

from analyzers.base import BaseAnalyzer
from core.exceptions import AnalyzerNotFoundError


# Registry of all analyzers: name -> class
_REGISTRY: Dict[str, Type[BaseAnalyzer]] = {}


def register(cls: Type[BaseAnalyzer]) -> Type[BaseAnalyzer]:
    """
    Decorator to register an analyzer class.
    
    Usage:
        @register
        class MyAnalyzer(BaseAnalyzer):
            @property
            def name(self) -> str:
                return "my_analyzer"
            
            def should_include(self, parsed) -> bool:
                ...
    """
    # Create temporary instance to get name
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
        error = AnalyzerNotFoundError(name)
        error.context["available"] = list(_REGISTRY.keys())
        raise error
    return _REGISTRY[name]()


def list_analyzers() -> List[str]:
    """
    List all registered analyzer names.
    
    Returns:
        Sorted list of analyzer names
    """
    return sorted(_REGISTRY.keys())


def get_all_analyzers() -> List[BaseAnalyzer]:
    """
    Get instances of all registered analyzers.
    
    Returns:
        List of analyzer instances (sorted by name)
    """
    return [_REGISTRY[name]() for name in sorted(_REGISTRY.keys())]


def analyzer_exists(name: str) -> bool:
    """
    Check if an analyzer exists.
    
    Args:
        name: Analyzer name
        
    Returns:
        True if analyzer is registered
    """
    return name in _REGISTRY


def get_analyzer_info() -> List[Dict]:
    """
    Get info about all registered analyzers.
    
    Returns:
        List of dicts with name, description, output_filename
    """
    info = []
    for name in sorted(_REGISTRY.keys()):
        instance = _REGISTRY[name]()
        info.append({
            "name": instance.name,
            "description": instance.description,
            "output_filename": instance.output_filename,
        })
    return info


# ============================================================
# Import analyzers to trigger registration
# Add new analyzers here as they are created
# ============================================================

from analyzers.open_redirect import OpenRedirectAnalyzer  # noqa: E402, F401
from analyzers.sensitive_paths import SensitivePathsAnalyzer  # noqa: E402, F401
from analyzers.sensitive_params import SensitiveParamsAnalyzer  # noqa: E402, F401
from analyzers.jwt import JWTAnalyzer  # noqa: E402, F401
from analyzers.documents import DocumentsAnalyzer  # noqa: E402, F401
from analyzers.emails import EmailsAnalyzer  # noqa: E402, F401
from analyzers.robots import RobotsAnalyzer  # noqa: E402, F401
from analyzers.params import ParamsAnalyzer  # noqa: E402, F401
from analyzers.ssrf import SSRFAnalyzer  # noqa: E402, F401
from analyzers.idor import IDORAnalyzer  # noqa: E402, F401
from analyzers.api_endpoints import APIEndpointsAnalyzer  # noqa: E402, F401
from analyzers.js_files import JSFilesAnalyzer  # noqa: E402, F401
from analyzers.backup_files import BackupFilesAnalyzer  # noqa: E402, F401
from analyzers.lfi import LFIAnalyzer  # noqa: E402, F401
from analyzers.sqli import SQLiAnalyzer  # noqa: E402, F401


__all__ = [
    # Base class
    "BaseAnalyzer",
    # Registry functions
    "register",
    "get_analyzer",
    "list_analyzers",
    "get_all_analyzers",
    "analyzer_exists",
    "get_analyzer_info",
]
