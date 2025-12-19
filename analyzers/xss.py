# analyzers/xss.py
"""
XSS Candidates analyzer.

Detects URLs with parameters commonly targeted for Cross-Site Scripting attacks.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class XSSAnalyzer(BaseAnalyzer):
    """
    Detect URLs with XSS-prone parameters.
    
    Matches URLs with parameters that commonly reflect user input:
    - Search, query params
    - Message, comment, text params
    - Name, title params
    - Error, debug params
    """
    
    # Parameters commonly vulnerable to XSS
    XSS_PARAMS = frozenset({
        # Search/query
        "q", "query", "search", "s", "keyword", "keywords",
        "term", "find", "filter",
        
        # Text content
        "message", "msg", "text", "body", "content",
        "comment", "description", "desc", "note", "notes",
        "title", "subject", "headline",
        
        # User input
        "name", "username", "user", "email", "input",
        "value", "data", "html", "code",
        
        # Display
        "error", "err", "warning", "info", "alert",
        "success", "status", "result", "output",
        
        # Callback/reflection
        "callback", "cb", "jsonp", "func", "function",
        "handler", "action",
        
        # URL params that reflect
        "url", "link", "href", "src", "redirect",
        "return", "next", "goto", "target",
    })
    
    @property
    def name(self) -> str:
        return "xss"
    
    @property
    def description(self) -> str:
        return "Detect XSS-prone parameters"
    
    @property
    def output_filename(self) -> str:
        return "xss_candidates.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL has XSS-prone parameters."""
        return bool(parsed.param_keys_lower & self.XSS_PARAMS)
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract XSS param details."""
        found = parsed.param_keys_lower & self.XSS_PARAMS
        if found:
            return {"xss_params": list(found)}
        return None
