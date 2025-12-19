# services/analysis.py
"""
Analysis orchestration service.

Coordinates running analyzers on targets:
- Single analyzer execution
- Batch analysis (all analyzers)
- Result management
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional, Callable

from storage.base import BaseStorage
from core.types import Target, AnalysisResult
from core.exceptions import TargetNotFoundError, AnalyzerNotFoundError
from analyzers import (
    get_analyzer, 
    list_analyzers, 
    get_all_analyzers,
    analyzer_exists,
    get_analyzer_info,
)


class AnalysisService:
    """
    Service for running URL analysis.
    
    Coordinates between storage and analyzers to:
    - Run single or multiple analyzers
    - Save results automatically
    - Provide progress feedback
    """
    
    def __init__(self, storage: BaseStorage):
        """
        Initialize analysis service.
        
        Args:
            storage: Storage backend instance
        """
        self.storage = storage
    
    def run_analyzer(
        self,
        scope: str,
        analyzer_name: str,
        input_name: str = "urls",
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> AnalysisResult:
        """
        Run a single analyzer on target URLs.
        
        Args:
            scope: Target scope
            analyzer_name: Name of analyzer to run
            input_name: Input URL file name (default: "urls")
            progress_callback: Optional progress callback
            
        Returns:
            AnalysisResult with matched URLs
            
        Raises:
            TargetNotFoundError: If target doesn't exist
            AnalyzerNotFoundError: If analyzer doesn't exist
        """
        # Validate
        if not self.storage.scope_exists(scope):
            raise TargetNotFoundError(scope)
        
        if not analyzer_exists(analyzer_name):
            raise AnalyzerNotFoundError(analyzer_name)
        
        # Load target config
        target = self._get_target(scope)
        
        # Get analyzer
        analyzer = get_analyzer(analyzer_name)
        
        # Stream URLs
        urls = self.storage.iter_urls(scope, input_name)
        
        # Run analysis
        result = analyzer.analyze(urls, target, progress_callback)
        
        # Save results
        self.storage.save_analysis(scope, result)
        
        return result
    
    def run_all_analyzers(
        self,
        scope: str,
        input_name: str = "urls",
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> List[AnalysisResult]:
        """
        Run all registered analyzers on target.
        
        Args:
            scope: Target scope
            input_name: Input URL file name
            progress_callback: Callback(analyzer_name, current, total)
            
        Returns:
            List of AnalysisResults
        """
        if not self.storage.scope_exists(scope):
            raise TargetNotFoundError(scope)
        
        results = []
        analyzers = list_analyzers()
        
        for i, name in enumerate(analyzers):
            # Wrap progress callback
            def wrapped_progress(current: int, total: int) -> None:
                if progress_callback:
                    progress_callback(name, current, total)
            
            result = self.run_analyzer(scope, name, input_name, wrapped_progress)
            results.append(result)
        
        return results
    
    def get_analysis_result(
        self, scope: str, analyzer_name: str
    ) -> Optional[AnalysisResult]:
        """
        Get saved analysis result.
        
        Args:
            scope: Target scope
            analyzer_name: Analyzer name
            
        Returns:
            AnalysisResult or None if not found
        """
        return self.storage.load_analysis(scope, analyzer_name)
    
    def list_analyses(self, scope: str) -> List[Dict[str, Any]]:
        """
        List all analyses for a target with summary.
        
        Args:
            scope: Target scope
            
        Returns:
            List of analysis summaries
        """
        if not self.storage.scope_exists(scope):
            raise TargetNotFoundError(scope)
        
        analyses = []
        
        for name in self.storage.list_analyses(scope):
            result = self.storage.load_analysis(scope, name)
            if result:
                analyses.append({
                    "analyzer_name": name,
                    "match_count": result.match_count,
                    "total_processed": result.total_processed,
                    "match_rate": round(result.match_rate, 2),
                    "timestamp": result.timestamp,
                })
        
        return analyses
    
    def get_available_analyzers(self) -> List[Dict[str, Any]]:
        """
        Get info about all available analyzers.
        
        Returns:
            List of analyzer info dicts
        """
        return get_analyzer_info()
    
    def delete_analysis(self, scope: str, analyzer_name: str) -> None:
        """
        Delete analysis result.
        
        Args:
            scope: Target scope
            analyzer_name: Analyzer name
        """
        # Delete URL file
        url_path = self.storage.get_scope_path(scope) / f"{analyzer_name}.txt"
        if url_path.exists():
            url_path.unlink()
        
        # Delete meta file
        meta_path = self.storage.get_scope_path(scope) / f"{analyzer_name}.meta.json"
        if meta_path.exists():
            meta_path.unlink()
    
    def _get_target(self, scope: str) -> Target:
        """Get Target object from scope."""
        metadata = self.storage.load_json(scope, "target_meta") or {}
        
        return Target(
            scope=scope,
            include_external=metadata.get("include_external", False),
            allow_subdomains=metadata.get("allow_subdomains", []),
            deny_subdomains=metadata.get("deny_subdomains", []),
            metadata=metadata,
        )
