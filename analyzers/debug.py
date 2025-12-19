# analyzers/debug.py
"""
Debug/Error Endpoints analyzer.

Detects URLs that may expose debug information, stack traces, or error details.
"""

from __future__ import annotations

import re
from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class DebugAnalyzer(BaseAnalyzer):
    """
    Detect debug and error-related URLs.
    
    Matches URLs with:
    - Debug paths (phpinfo, debug, trace)
    - Error pages
    - Stack trace indicators
    - Info disclosure paths
    """
    
    # Debug path patterns
    DEBUG_PATH_PATTERNS = [
        # PHP
        r"/phpinfo",
        r"/info\.php",
        r"/test\.php",
        r"/debug\.php",
        
        # General debug
        r"/debug",
        r"/trace",
        r"/profiler",
        r"/console",
        r"/shell",
        r"/terminal",
        
        # Status/health
        r"/status",
        r"/health",
        r"/healthcheck",
        r"/ping",
        r"/metrics",
        r"/stats",
        r"/actuator",
        
        # Env/config
        r"/env",
        r"/config",
        r"/settings",
        r"\.env",
        r"\.config",
        
        # Logs
        r"/log",
        r"/logs",
        r"\.log$",
        r"/error",
        r"/errors",
        
        # Info
        r"/info",
        r"/version",
        r"/about",
        r"/server-info",
        r"/server-status",
        
        # Dev tools
        r"/_debugbar",
        r"/_profiler",
        r"/elmah",
        r"/telescope",
        r"/horizon",
    ]
    
    RE_DEBUG_PATTERNS = [re.compile(p, re.I) for p in DEBUG_PATH_PATTERNS]
    
    @property
    def name(self) -> str:
        return "debug"
    
    @property
    def description(self) -> str:
        return "Detect debug/info disclosure endpoints"
    
    @property
    def output_filename(self) -> str:
        return "debug_endpoints.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL is a debug/info endpoint."""
        for pattern in self.RE_DEBUG_PATTERNS:
            if pattern.search(parsed.path):
                return True
        return False
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract debug endpoint type."""
        path_lower = parsed.path.lower()
        
        categories = []
        if any(x in path_lower for x in ["phpinfo", "info.php", "test.php"]):
            categories.append("php")
        if any(x in path_lower for x in ["/debug", "/trace", "/profiler"]):
            categories.append("debug")
        if any(x in path_lower for x in ["/log", ".log", "/error"]):
            categories.append("logs")
        if any(x in path_lower for x in ["/env", ".env", "/config"]):
            categories.append("config")
        if any(x in path_lower for x in ["/status", "/health", "/metrics"]):
            categories.append("status")
        
        return {"categories": categories or ["general"]}
