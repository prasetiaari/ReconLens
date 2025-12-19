# analyzers/ssrf.py
"""
SSRF Candidates analyzer.

Detects URLs with parameters commonly used in Server-Side Request Forgery attacks.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class SSRFAnalyzer(BaseAnalyzer):
    """
    Detect URLs with SSRF-prone parameters.
    
    Matches URLs containing parameters commonly used in SSRF:
    - url, uri, path, dest, redirect
    - host, server, target
    - fetch, load, request
    - proxy, forward
    """
    
    # Parameters commonly used in SSRF
    SSRF_PARAMS = frozenset({
        # URL-related
        "url", "uri", "path", "dest", "destination", "redirect",
        "redirect_url", "redirect_uri", "return", "return_url",
        "next", "target", "link", "href", "location",
        
        # Host-related
        "host", "hostname", "server", "domain", "endpoint",
        "ip", "address", "addr",
        
        # Action-related
        "fetch", "load", "request", "req", "get", "retrieve",
        "read", "download", "file", "doc", "document",
        
        # Proxy-related
        "proxy", "forward", "proxy_url", "proxy_host",
        "callback", "webhook", "callback_url",
        
        # Image/resource
        "img", "image", "src", "source", "avatar",
        "icon", "logo", "picture", "photo",
        
        # API-related
        "api", "api_url", "service", "service_url",
        "site", "website", "page", "view",
    })
    
    @property
    def name(self) -> str:
        return "ssrf"
    
    @property
    def description(self) -> str:
        return "Detect URLs with SSRF-prone parameters"
    
    @property
    def output_filename(self) -> str:
        return "ssrf_candidates.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL has any SSRF-prone parameters."""
        return bool(parsed.param_keys_lower & self.SSRF_PARAMS)
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract SSRF params and check for URL values."""
        found = parsed.param_keys_lower & self.SSRF_PARAMS
        if found:
            # Check if any values look like URLs
            has_url_value = False
            has_internal_ip = False
            
            for key in found:
                for k, values in parsed.params.items():
                    if k.lower() == key:
                        for v in values:
                            v_lower = v.lower()
                            if v.startswith(("http://", "https://", "//")):
                                has_url_value = True
                            if any(ip in v_lower for ip in ["127.0.0.1", "localhost", "0.0.0.0", "192.168.", "10.", "172.16."]):
                                has_internal_ip = True
            
            return {
                "ssrf_params": list(found),
                "has_url_value": has_url_value,
                "has_internal_ip": has_internal_ip,
            }
        return None
