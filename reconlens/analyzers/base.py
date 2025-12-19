# reconlens/analyzers/base.py
"""
Base analyzer class.

All analyzer modules inherit from BaseAnalyzer.
Subclasses only need to implement:
- name: str property
- should_include(parsed: ParsedURL) -> bool

The common analysis loop is handled by the base class.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Optional, Callable

from reconlens.core.types import ParsedURL, AnalysisResult, Target
from reconlens.core.url import parse_url, is_static_asset
from reconlens.core.scope import is_in_target_scope


class BaseAnalyzer(ABC):
    """
    Abstract base class for all URL analyzers.
    
    Subclasses must implement:
    - name: Unique identifier for the analyzer
    - should_include: Detection logic for a single URL
    
    The analyze() method handles:
    - URL parsing
    - Scope filtering
    - Progress reporting
    - Result collection
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """
        Unique identifier for this analyzer.
        Used for registration, output filenames, etc.
        """
        pass
    
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
    
    @abstractmethod
    def should_include(self, parsed: ParsedURL) -> bool:
        """
        Determine if a parsed URL should be included in results.
        
        This is the ONLY method subclasses must implement.
        All common logic (parsing, scope check, etc.) is in analyze().
        
        Args:
            parsed: Parsed and validated URL
            
        Returns:
            True if URL matches this analyzer's criteria
        """
        pass
    
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
        
        Subclasses should NOT override this unless absolutely necessary.
        
        Args:
            urls: Iterable of raw URL strings
            target: Target scope configuration
            progress_callback: Optional callback(current, total) for progress
            
        Returns:
            AnalysisResult with matched URLs
        """
        matched: set[str] = set()
        total = 0
        skipped_scope = 0
        skipped_invalid = 0
        skipped_static = 0
        
        for raw_url in urls:
            total += 1
            
            # Parse URL
            parsed = parse_url(raw_url)
            if not parsed.is_valid:
                skipped_invalid += 1
                continue
            
            # Scope check
            if not is_in_target_scope(parsed.host, target):
                skipped_scope += 1
                continue
            
            # Skip static assets if configured
            if self.skip_static_assets and is_static_asset(parsed.path):
                skipped_static += 1
                continue
            
            # Analyzer-specific check
            if self.should_include(parsed):
                matched.add(parsed.raw)
            
            # Progress callback
            if progress_callback and total % 1000 == 0:
                progress_callback(total, 0)  # 0 = unknown total
        
        return AnalysisResult(
            analyzer_name=self.name,
            matched_urls=matched,
            total_processed=total,
            metadata={
                "skipped_invalid": skipped_invalid,
                "skipped_scope": skipped_scope,
                "skipped_static": skipped_static,
            }
        )
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name!r})>"
