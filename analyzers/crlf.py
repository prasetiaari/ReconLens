# analyzers/crlf.py
"""
CRLF Injection Candidates analyzer.

Detects URLs with parameters that might be vulnerable to CRLF injection.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class CRLFAnalyzer(BaseAnalyzer):
    """
    Detect URLs with CRLF injection-prone parameters.
    
    Matches URLs with HTTP header-related parameters.
    """
    
    # Parameters that might be used in HTTP headers
    CRLF_PARAMS = frozenset({
        # Redirect/Location
        "url", "redirect", "redirect_url", "return", "return_url",
        "next", "goto", "target", "dest", "destination",
        "location", "uri", "path",
        
        # Headers
        "header", "headers", "host", "origin",
        "referer", "referrer", "user-agent", "ua",
        
        # Cookie-related
        "cookie", "session", "set-cookie",
        
        # Content type
        "content-type", "contenttype", "type",
        "accept", "charset", "encoding",
    })
    
    @property
    def name(self) -> str:
        return "crlf"
    
    @property
    def description(self) -> str:
        return "Detect CRLF injection-prone parameters"
    
    @property
    def output_filename(self) -> str:
        return "crlf_candidates.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL has CRLF-prone parameters."""
        return bool(parsed.param_keys_lower & self.CRLF_PARAMS)
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract CRLF param details."""
        found = parsed.param_keys_lower & self.CRLF_PARAMS
        if found:
            return {"crlf_params": list(found)}
        return None
