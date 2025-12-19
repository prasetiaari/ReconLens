# analyzers/open_redirect.py
"""
Open Redirect analyzer.

Detects URLs with redirect-prone parameters that could be
vulnerable to open redirect attacks.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class OpenRedirectAnalyzer(BaseAnalyzer):
    """
    Detect URLs with redirect-prone parameters.
    
    Matches URLs containing parameters commonly used for redirects,
    such as: url, next, redirect, return, callback, dest, etc.
    
    Can also detect if the parameter value looks like an external URL.
    """
    
    # Parameters commonly used for redirects
    REDIRECT_PARAMS = frozenset({
        # Common
        "url", "next", "redirect", "return", "continue", "callback",
        "dest", "destination", "target", "go", "link", "to", "redir",
        
        # URL variations
        "returnurl", "returnto", "return_url", "return_to",
        "redirect_url", "redirect_uri", "redirect_to",
        "success_url", "failure_url", "cancel_url",
        "checkout_url", "continue_url",
        
        # OAuth/SSO
        "service", "redirect_uri", "post_logout_redirect_uri",
        
        # Short forms
        "u", "ru", "ref", "site", "path",
        "forward", "forward_url", "jump", "jump_url",
        "out", "outurl", "back", "back_url",
    })
    
    @property
    def name(self) -> str:
        return "open_redirect"
    
    @property
    def description(self) -> str:
        return "Detect URLs with redirect-prone parameters"
    
    @property
    def output_filename(self) -> str:
        return "open_redirect_candidates.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL has any redirect-prone parameters."""
        return bool(parsed.param_keys_lower & self.REDIRECT_PARAMS)
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract which redirect params were found."""
        found = parsed.param_keys_lower & self.REDIRECT_PARAMS
        if found:
            # Check if any values look like URLs
            has_url_value = False
            for key in found:
                # Find actual key (case-insensitive)
                for k, values in parsed.params.items():
                    if k.lower() == key:
                        for v in values:
                            if v.startswith(("http://", "https://", "//")):
                                has_url_value = True
                                break
            
            return {
                "redirect_params": list(found),
                "has_url_value": has_url_value,
            }
        return None
