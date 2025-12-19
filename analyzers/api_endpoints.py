# analyzers/api_endpoints.py
"""
API Endpoints analyzer.

Detects URLs that appear to be API endpoints for further testing.
"""

from __future__ import annotations

import re
from typing import Dict, Any, Optional, List

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class APIEndpointsAnalyzer(BaseAnalyzer):
    """
    Detect URLs that are API endpoints.
    
    Matches URLs with:
    - API path patterns (/api/, /v1/, /rest/, /graphql)
    - JSON/XML response indicators
    - Common API conventions
    """
    
    # Path patterns indicating API endpoints
    API_PATH_PATTERNS = [
        # Versioned APIs
        r"/api/",
        r"/api$",
        r"/v\d+/",
        r"/v\d+$",
        r"/api/v\d+",
        
        # REST conventions
        r"/rest/",
        r"/restful/",
        r"/json/",
        r"/xml/",
        r"/rpc/",
        
        # GraphQL
        r"/graphql",
        r"/gql",
        r"/query",
        
        # Common endpoint patterns
        r"/api-gateway/",
        r"/backend/",
        r"/service/",
        r"/services/",
        r"/internal/",
        r"/_api/",
        r"/-/",
        
        # Framework-specific
        r"/wp-json/",  # WordPress
        r"/jsonapi/",  # Drupal
        r"/_next/data/",  # Next.js
        r"/api/trpc/",  # tRPC
    ]
    
    # Compiled patterns
    RE_API_PATTERNS = [re.compile(p, re.I) for p in API_PATH_PATTERNS]
    
    # File extensions indicating API responses
    API_EXTENSIONS = frozenset({
        "json", "xml", "yaml", "yml",
    })
    
    @property
    def name(self) -> str:
        return "api_endpoints"
    
    @property
    def description(self) -> str:
        return "Detect API endpoint URLs"
    
    @property
    def output_filename(self) -> str:
        return "api_endpoints.txt"
    
    @property
    def skip_static_assets(self) -> bool:
        """Don't skip - we want JSON/XML files."""
        return False
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL appears to be an API endpoint."""
        path = parsed.path
        
        # Check path patterns
        for pattern in self.RE_API_PATTERNS:
            if pattern.search(path):
                return True
        
        # Check extension
        if "." in path:
            ext = path.rsplit(".", 1)[-1].lower()
            if ext in self.API_EXTENSIONS:
                return True
        
        return False
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract API type information."""
        path = parsed.path.lower()
        
        api_types: List[str] = []
        
        if "/graphql" in path or "/gql" in path:
            api_types.append("graphql")
        if "/rest" in path:
            api_types.append("rest")
        if "/wp-json" in path:
            api_types.append("wordpress")
        if "/jsonapi" in path:
            api_types.append("drupal")
        if "/_next/data" in path:
            api_types.append("nextjs")
        if "/api/trpc" in path:
            api_types.append("trpc")
        
        # Extract version if present
        version_match = re.search(r"/v(\d+)", path)
        version = version_match.group(1) if version_match else None
        
        if api_types or version:
            return {
                "api_types": api_types or ["generic"],
                "version": version,
            }
        
        return {"api_types": ["generic"]}
