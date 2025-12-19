# analyzers/idor.py
"""
IDOR Candidates analyzer.

Detects URLs with numeric or UUID identifiers that may be vulnerable
to Insecure Direct Object Reference attacks.
"""

from __future__ import annotations

import re
from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


# Patterns for identifiers
RE_NUMERIC_ID = re.compile(r'^\d+$')
RE_UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
RE_SHORT_UUID = re.compile(r'^[0-9a-f]{24,32}$', re.I)  # MongoDB ObjectId, etc.
RE_PATH_ID = re.compile(r'/(\d+)(?:/|$)')  # /users/123/profile


@register
class IDORAnalyzer(BaseAnalyzer):
    """
    Detect URLs with potential IDOR vulnerabilities.
    
    Matches URLs containing:
    - Numeric IDs in parameters (id=123, user_id=456)
    - UUIDs in parameters
    - Numeric IDs in path segments (/user/123/orders)
    """
    
    # Parameters commonly containing object references
    IDOR_PARAMS = frozenset({
        # Generic IDs
        "id", "ids", "uid", "uuid", "guid",
        
        # User-related
        "user_id", "userid", "user", "account_id", "account",
        "member_id", "member", "customer_id", "customer",
        "profile_id", "profile", "owner_id", "owner",
        
        # Object-related
        "order_id", "order", "invoice_id", "invoice",
        "document_id", "document", "doc_id", "doc",
        "file_id", "file", "image_id", "image",
        "item_id", "item", "product_id", "product",
        "post_id", "post", "comment_id", "comment",
        "message_id", "message", "msg_id", "thread_id",
        
        # Organization-related
        "org_id", "org", "organization_id", "organization",
        "company_id", "company", "team_id", "team",
        "group_id", "group", "project_id", "project",
        
        # Record-related
        "record_id", "record", "entry_id", "entry",
        "ref", "reference", "no", "number",
    })
    
    @property
    def name(self) -> str:
        return "idor"
    
    @property
    def description(self) -> str:
        return "Detect URLs with potential IDOR vulnerabilities"
    
    @property
    def output_filename(self) -> str:
        return "idor_candidates.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL has identifiers that could be IDOR targets."""
        # Check parameters
        for key in parsed.param_keys_lower:
            if key in self.IDOR_PARAMS:
                # Get the value
                for k, values in parsed.params.items():
                    if k.lower() == key:
                        for v in values:
                            if self._is_identifier(v):
                                return True
        
        # Check path for numeric IDs
        if RE_PATH_ID.search(parsed.path):
            return True
        
        return False
    
    def _is_identifier(self, value: str) -> bool:
        """Check if value looks like an identifier."""
        v = value.strip()
        if not v:
            return False
        
        # Numeric ID
        if RE_NUMERIC_ID.match(v) and len(v) <= 15:
            return True
        
        # UUID
        if RE_UUID.match(v):
            return True
        
        # Short UUID (MongoDB ObjectId, etc.)
        if RE_SHORT_UUID.match(v):
            return True
        
        return False
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract identifier details."""
        idor_params = []
        id_types = set()
        
        # Check params
        for key in parsed.param_keys_lower:
            if key in self.IDOR_PARAMS:
                for k, values in parsed.params.items():
                    if k.lower() == key:
                        for v in values:
                            if RE_NUMERIC_ID.match(v):
                                idor_params.append(key)
                                id_types.add("numeric")
                            elif RE_UUID.match(v):
                                idor_params.append(key)
                                id_types.add("uuid")
                            elif RE_SHORT_UUID.match(v):
                                idor_params.append(key)
                                id_types.add("short_uuid")
        
        # Check path
        path_ids = RE_PATH_ID.findall(parsed.path)
        if path_ids:
            id_types.add("path_numeric")
        
        if idor_params or path_ids:
            return {
                "idor_params": list(set(idor_params)),
                "path_ids": path_ids[:3],  # Limit
                "id_types": list(id_types),
            }
        return None
