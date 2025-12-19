# reconlens/analyzers/open_redirect.py
"""
Open Redirect analyzer.

Detects URLs with redirect-prone parameters that could be
vulnerable to open redirect attacks.
"""

from __future__ import annotations

from reconlens.analyzers.base import BaseAnalyzer
from reconlens.analyzers import register
from reconlens.core.types import ParsedURL


@register
class OpenRedirectAnalyzer(BaseAnalyzer):
    """
    Detect URLs with redirect-prone parameters.
    
    Matches URLs containing parameters commonly used for redirects,
    such as: url, next, redirect, return, callback, dest, etc.
    """
    
    # Parameters commonly used for redirects
    REDIRECT_PARAMS = frozenset({
        "url", "next", "redirect", "return", "continue", "callback",
        "dest", "destination", "target", "go", "link", "to", "redir",
        "returnurl", "returnto", "return_url", "return_to",
        "redirect_url", "redirect_uri", "redirect_to",
        "service", "u", "ru", "ref", "site", "path",
        "forward", "forward_url", "jump", "jump_url",
        "out", "outurl", "checkout_url", "success_url",
        "failure_url", "cancel_url", "back", "back_url",
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
        """
        Check if URL has any redirect-prone parameters.
        
        Uses case-insensitive matching against known redirect param names.
        """
        return bool(parsed.param_keys_lower & self.REDIRECT_PARAMS)
