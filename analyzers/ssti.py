# analyzers/ssti.py
"""
SSTI (Server-Side Template Injection) Candidates analyzer.

Detects URLs with parameters commonly used in template engines.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class SSTIAnalyzer(BaseAnalyzer):
    """
    Detect URLs with SSTI-prone parameters.
    
    Matches URLs with parameters commonly used in template rendering:
    - Template, theme, layout params
    - Email template params
    - Render, view params
    """
    
    # Parameters commonly used with templates
    SSTI_PARAMS = frozenset({
        # Template params
        "template", "tpl", "tmpl", "layout", "theme",
        "skin", "style", "view", "render",
        
        # Email templates
        "email_template", "mail_template", "notification",
        "email_body", "mail_body", "email_subject",
        
        # Content
        "content", "body", "text", "message", "msg",
        "html", "format", "output",
        
        # Preview/render
        "preview", "display", "show", "print",
        
        # Lang/locale
        "lang", "language", "locale", "i18n",
    })
    
    @property
    def name(self) -> str:
        return "ssti"
    
    @property
    def description(self) -> str:
        return "Detect SSTI-prone template parameters"
    
    @property
    def output_filename(self) -> str:
        return "ssti_candidates.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL has SSTI-prone parameters."""
        return bool(parsed.param_keys_lower & self.SSTI_PARAMS)
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract SSTI param details."""
        found = parsed.param_keys_lower & self.SSTI_PARAMS
        if found:
            return {"ssti_params": list(found)}
        return None
