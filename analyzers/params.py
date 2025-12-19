# analyzers/params.py
"""
Interesting Parameters analyzer.

Collects unique parameter names from URLs, filtering out common noise
like UTM tracking, cache busters, etc.
"""

from __future__ import annotations

from typing import Dict, Any, Optional, FrozenSet

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class ParamsAnalyzer(BaseAnalyzer):
    """
    Collect unique parameter names from URLs.
    
    Filters out common noise parameters like:
    - UTM tracking (utm_source, utm_medium, etc.)
    - Cache busters (cb, _, v, ver)
    - Social tracking (gclid, fbclid)
    """
    
    # Parameters to exclude (noise)
    EXCLUDE_PARAMS = frozenset({
        # Cache busters
        "_", "__", "cb", "v", "ver", "version", "t", "ts", "timestamp",
        "nocache", "no_cache", "cache", "rand", "random",
        
        # UTM tracking
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "utm_id", "utm_cid",
        
        # Social/ads tracking  
        "gclid", "fbclid", "msclkid", "twclid", "li_fat_id",
        "mc_cid", "mc_eid", "dclid",
        
        # Analytics
        "ref", "referrer", "source", "campaign",
        "_ga", "_gl", "_gac", "gtm",
        
        # Pagination (usually not interesting)
        "page", "p", "offset", "limit", "per_page", "pagesize",
    })
    
    @property
    def name(self) -> str:
        return "params"
    
    @property
    def description(self) -> str:
        return "Collect unique parameter names (excluding noise)"
    
    @property
    def output_filename(self) -> str:
        return "params.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Include URL if it has any non-excluded parameters."""
        interesting = parsed.param_keys_lower - self.EXCLUDE_PARAMS
        return bool(interesting)
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract the interesting parameter names."""
        interesting = parsed.param_keys_lower - self.EXCLUDE_PARAMS
        if interesting:
            return {
                "params": list(interesting),
                "param_count": len(interesting),
            }
        return None
