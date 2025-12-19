# analyzers/xxe.py
"""
XXE (XML External Entity) Candidates analyzer.

Detects URLs that may process XML input.
"""

from __future__ import annotations

import re
from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL
from core.url_utils import get_extension


@register
class XXEAnalyzer(BaseAnalyzer):
    """
    Detect URLs vulnerable to XXE.
    
    Matches URLs with:
    - XML file extensions
    - XML-related parameters
    - SOAP endpoints
    """
    
    # XML extensions
    XML_EXTENSIONS = frozenset({
        "xml", "xsl", "xslt", "dtd", "xsd",
        "svg", "rss", "atom", "soap", "wsdl",
    })
    
    # XXE-related params
    XXE_PARAMS = frozenset({
        "xml", "xmldata", "data", "content", "body",
        "soap", "wsdl", "rss", "feed",
        "import", "export", "parse", "load",
    })
    
    # Path patterns
    XXE_PATH_PATTERNS = [
        r"/soap",
        r"/wsdl",
        r"/xml",
        r"/rss",
        r"/feed",
        r"/atom",
        r"/sitemap",
    ]
    
    RE_XXE_PATTERNS = [re.compile(p, re.I) for p in XXE_PATH_PATTERNS]
    
    @property
    def name(self) -> str:
        return "xxe"
    
    @property
    def description(self) -> str:
        return "Detect XXE-prone XML endpoints"
    
    @property
    def output_filename(self) -> str:
        return "xxe_candidates.txt"
    
    @property
    def skip_static_assets(self) -> bool:
        return False
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL may process XML."""
        # Check extension
        ext = get_extension(parsed.path)
        if ext and ext in self.XML_EXTENSIONS:
            return True
        
        # Check path patterns
        for pattern in self.RE_XXE_PATTERNS:
            if pattern.search(parsed.path):
                return True
        
        # Check params
        if parsed.param_keys_lower & self.XXE_PARAMS:
            return True
        
        return False
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract XXE details."""
        ext = get_extension(parsed.path)
        found_params = parsed.param_keys_lower & self.XXE_PARAMS
        
        return {
            "extension": ext,
            "xxe_params": list(found_params) if found_params else [],
        }
