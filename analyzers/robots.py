# analyzers/robots.py
"""
Robots.txt analyzer.

Detects URLs pointing to robots.txt files.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class RobotsAnalyzer(BaseAnalyzer):
    """
    Detect URLs pointing to robots.txt files.
    
    robots.txt files can reveal:
    - Hidden paths/directories
    - Admin panels
    - API endpoints
    - Staging environments
    """
    
    @property
    def name(self) -> str:
        return "robots"
    
    @property
    def description(self) -> str:
        return "Detect URLs pointing to robots.txt files"
    
    @property
    def output_filename(self) -> str:
        return "robots.txt"
    
    @property
    def skip_static_assets(self) -> bool:
        return False
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL points to robots.txt."""
        path_lower = parsed.path.lower()
        return path_lower.endswith("/robots.txt") or path_lower == "/robots.txt"
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract host for grouping."""
        return {
            "host": parsed.host,
            "full_url": f"{parsed.scheme}://{parsed.netloc}/robots.txt",
        }
