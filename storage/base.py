# storage/base.py
"""
Abstract base class for storage implementations.

Defines the interface that all storage backends must implement.
This enables swapping storage implementations without changing business logic.

Enterprise-grade features:
- Protocol/interface pattern
- Comprehensive operations for all data types
- Streaming support for large datasets
- Atomic operations where possible
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import (
    Set, List, Dict, Any, Optional, Iterator, 
    TYPE_CHECKING, Union
)

if TYPE_CHECKING:
    from core.types import AnalysisResult, ProbeResult, Target


class BaseStorage(ABC):
    """
    Abstract interface for data persistence.
    
    All storage implementations must implement these methods.
    This allows swapping between file-based, SQLite, PostgreSQL, etc.
    without changing any business logic.
    
    Naming conventions:
    - scope: Target domain identifier (e.g., "example.com")
    - name: Data identifier within scope (e.g., "urls", "subdomains")
    """
    
    # ==================== Scope/Target Operations ====================
    
    @abstractmethod
    def list_scopes(self) -> List[str]:
        """
        List all target scopes.
        
        Returns:
            List of scope names (e.g., ["example.com", "test.com"])
        """
        pass
    
    @abstractmethod
    def scope_exists(self, scope: str) -> bool:
        """Check if a scope exists."""
        pass
    
    @abstractmethod
    def create_scope(self, scope: str) -> None:
        """Create a new scope (target directory/namespace)."""
        pass
    
    @abstractmethod
    def delete_scope(self, scope: str) -> None:
        """Delete a scope and all its data."""
        pass
    
    # ==================== URL Operations ====================
    
    @abstractmethod
    def save_urls(
        self,
        scope: str,
        name: str,
        urls: Set[str],
        append: bool = False,
    ) -> int:
        """
        Save a set of URLs.
        
        Args:
            scope: Target scope
            name: Data identifier (e.g., "urls", "open_redirect")
            urls: Set of URLs to save
            append: If True, append to existing; if False, overwrite
            
        Returns:
            Number of URLs saved
        """
        pass
    
    @abstractmethod
    def load_urls(self, scope: str, name: str) -> Set[str]:
        """
        Load all URLs into memory.
        
        Args:
            scope: Target scope
            name: Data identifier
            
        Returns:
            Set of URLs
        """
        pass
    
    @abstractmethod
    def iter_urls(self, scope: str, name: str) -> Iterator[str]:
        """
        Iterate URLs without loading all into memory.
        
        Use for large datasets to avoid memory issues.
        
        Args:
            scope: Target scope
            name: Data identifier
            
        Yields:
            URL strings one at a time
        """
        pass
    
    @abstractmethod
    def url_count(self, scope: str, name: str) -> int:
        """Get count of URLs without loading them."""
        pass
    
    @abstractmethod
    def urls_exist(self, scope: str, name: str) -> bool:
        """Check if URL data exists."""
        pass
    
    # ==================== Analysis Operations ====================
    
    @abstractmethod
    def save_analysis(self, scope: str, result: "AnalysisResult") -> None:
        """
        Save analysis result.
        
        Saves both the URL list and metadata.
        """
        pass
    
    @abstractmethod
    def load_analysis(
        self, scope: str, analyzer_name: str
    ) -> Optional["AnalysisResult"]:
        """
        Load analysis result.
        
        Returns None if not found.
        """
        pass
    
    @abstractmethod
    def list_analyses(self, scope: str) -> List[str]:
        """List all analyzer names that have results for this scope."""
        pass
    
    # ==================== Probe Operations ====================
    
    @abstractmethod
    def save_probe_result(self, scope: str, result: "ProbeResult") -> None:
        """Save a single probe result."""
        pass
    
    @abstractmethod
    def save_probe_results(
        self, scope: str, results: List["ProbeResult"]
    ) -> int:
        """
        Save multiple probe results.
        
        Returns:
            Number of results saved
        """
        pass
    
    @abstractmethod
    def load_probe_results(self, scope: str) -> List["ProbeResult"]:
        """Load all probe results for a scope."""
        pass
    
    @abstractmethod
    def iter_probe_results(self, scope: str) -> Iterator["ProbeResult"]:
        """Iterate probe results without loading all into memory."""
        pass
    
    # ==================== JSON/Dict Operations ====================
    
    @abstractmethod
    def save_json(
        self, scope: str, name: str, data: Union[Dict, List]
    ) -> None:
        """Save JSON-serializable data."""
        pass
    
    @abstractmethod
    def load_json(
        self, scope: str, name: str
    ) -> Optional[Union[Dict, List]]:
        """Load JSON data. Returns None if not found."""
        pass
    
    # ==================== Cache Operations ====================
    
    @abstractmethod
    def get_cache_path(self, scope: str) -> Path:
        """Get path to cache directory for a scope."""
        pass
    
    @abstractmethod
    def clear_cache(self, scope: str) -> None:
        """Clear cache for a scope."""
        pass
    
    # ==================== Utility ====================
    
    @abstractmethod
    def get_scope_path(self, scope: str) -> Path:
        """Get filesystem path for a scope (for compatibility)."""
        pass
