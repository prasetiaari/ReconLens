# analyzers/base.py
"""
Base analyzer class.

All analyzer modules inherit from BaseAnalyzer.
Subclasses only need to implement:
- name: str property
- should_include(parsed: ParsedURL) -> bool

The common analysis loop is handled by the base class.

Enterprise-grade features:
- Template Method pattern for consistent behavior
- Progress callback support
- Comprehensive metadata collection
- Configurable filtering options
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Optional, Callable, Set, Dict, Any
from datetime import datetime

from core.types import ParsedURL, AnalysisResult, Target
from core.url_utils import parse_url, is_static_asset
from core.scope import is_in_scope


class BaseAnalyzer(ABC):
    """
    Abstract base class for all URL analyzers.
    
    Subclasses must implement:
    - name: Unique identifier for the analyzer
    - should_include: Detection logic for a single URL
    
    The analyze() method handles:
    - URL parsing
    - Scope filtering
    - Static asset filtering
    - Progress reporting
    - Result collection
    - Metadata gathering
    
    Example:
        class MyAnalyzer(BaseAnalyzer):
            @property
            def name(self) -> str:
                return "my_analyzer"
            
            def should_include(self, parsed: ParsedURL) -> bool:
                return "admin" in parsed.path
    """
    
    # ==================== Abstract Properties ====================
    
    @property
    @abstractmethod
    def name(self) -> str:
        """
        Unique identifier for this analyzer.
        Used for registration, output filenames, storage keys.
        """
        pass
    
    # ==================== Optional Overrides ====================
    
    @property
    def description(self) -> str:
        """Human-readable description of what this analyzer detects."""
        return f"{self.name} analyzer"
    
    @property
    def output_filename(self) -> str:
        """Default output filename for results."""
        return f"{self.name}.txt"
    
    @property
    def skip_static_assets(self) -> bool:
        """Whether to skip static assets (images, css, js). Default True."""
        return True
    
    @property
    def version(self) -> str:
        """Analyzer version for tracking changes."""
        return "1.0.0"
    
    # ==================== Abstract Method ====================
    
    @abstractmethod
    def should_include(self, parsed: ParsedURL) -> bool:
        """
        Determine if a parsed URL should be included in results.
        
        This is the ONLY method subclasses MUST implement.
        All common logic (parsing, scope check, etc.) is in analyze().
        
        Args:
            parsed: Parsed and validated URL
            
        Returns:
            True if URL matches this analyzer's criteria
        """
        pass
    
    # ==================== Optional Hooks ====================
    
    def pre_analyze(self, target: Target) -> None:
        """
        Hook called before analysis starts.
        Override for setup logic.
        """
        pass
    
    def post_analyze(self, result: AnalysisResult) -> AnalysisResult:
        """
        Hook called after analysis completes.
        Override for post-processing.
        """
        return result
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """
        Extract additional metadata from matched URL.
        Override to collect extra information.
        """
        return None
    
    # ==================== Main Analysis Method ====================
    
    def analyze(
        self,
        urls: Iterable[str],
        target: Target,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> AnalysisResult:
        """
        Analyze URLs and return matching results.
        
        This method handles all common logic:
        - URL parsing and validation
        - Scope filtering  
        - Static asset filtering
        - Progress reporting
        - Result collection
        - Metadata gathering
        
        Subclasses should NOT override this unless absolutely necessary.
        Use pre_analyze/post_analyze hooks instead.
        
        Args:
            urls: Iterable of raw URL strings
            target: Target scope configuration
            progress_callback: Optional callback(current, total) for progress
            
        Returns:
            AnalysisResult with matched URLs and metadata
        """
        # Pre-analysis hook
        self.pre_analyze(target)
        
        # Statistics
        matched: Set[str] = set()
        url_metadata: Dict[str, Dict] = {}
        stats = {
            "total": 0,
            "skipped_invalid": 0,
            "skipped_scope": 0,
            "skipped_static": 0,
            "analyzed": 0,
        }
        
        for raw_url in urls:
            stats["total"] += 1
            
            # Parse URL
            parsed = parse_url(raw_url)
            if not parsed.is_valid:
                stats["skipped_invalid"] += 1
                continue
            
            # Scope check (unless include_external)
            if not target.include_external:
                if not is_in_scope(
                    parsed.host,
                    target.scope,
                    target.allow_subdomains or None,
                    target.deny_subdomains or None,
                ):
                    stats["skipped_scope"] += 1
                    continue
            
            # Skip static assets if configured
            if self.skip_static_assets and is_static_asset(parsed.path):
                stats["skipped_static"] += 1
                continue
            
            stats["analyzed"] += 1
            
            # Analyzer-specific check
            if self.should_include(parsed):
                matched.add(parsed.raw)
                
                # Collect optional metadata
                meta = self.extract_metadata(parsed)
                if meta:
                    url_metadata[parsed.raw] = meta
            
            # Progress callback (every 1000 URLs)
            if progress_callback and stats["total"] % 1000 == 0:
                progress_callback(stats["total"], 0)
        
        # Build result
        result = AnalysisResult(
            analyzer_name=self.name,
            matched_urls=matched,
            total_processed=stats["analyzed"],
            metadata={
                "stats": stats,
                "target_scope": target.scope,
                "analyzer_version": self.version,
                "url_metadata": url_metadata if url_metadata else None,
            },
            timestamp=datetime.utcnow().isoformat() + "Z",
        )
        
        # Post-analysis hook
        return self.post_analyze(result)
    
    # ==================== Utility Methods ====================
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name!r})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize analyzer info to dict."""
        return {
            "name": self.name,
            "description": self.description,
            "output_filename": self.output_filename,
            "version": self.version,
            "skip_static_assets": self.skip_static_assets,
        }
