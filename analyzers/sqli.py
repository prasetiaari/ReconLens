# analyzers/sqli.py
"""
SQLi Candidates analyzer.

Detects URLs with parameters commonly targeted for SQL injection attacks.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class SQLiAnalyzer(BaseAnalyzer):
    """
    Detect URLs with SQLi-prone parameters.
    
    Matches URLs containing parameters commonly used in SQL queries:
    - IDs and identifiers
    - Search/filter parameters
    - Sorting/ordering parameters
    """
    
    # Parameters commonly used in SQL queries
    SQLI_PARAMS = frozenset({
        # Identifiers
        "id", "uid", "userid", "user_id", "pid", "product_id",
        "cid", "category_id", "item_id", "order_id", "invoice_id",
        "ref", "reference", "no", "num", "number",
        
        # Search/filter
        "search", "query", "q", "keyword", "term", "filter",
        "find", "lookup", "name", "title", "where",
        
        # Sorting
        "sort", "sortby", "sort_by", "order", "orderby", "order_by",
        "dir", "direction", "asc", "desc",
        
        # Selection
        "select", "column", "col", "field", "fields",
        "table", "from", "join",
        
        # Pagination
        "limit", "offset", "count", "max", "min",
        
        # Category/type
        "category", "cat", "type", "group", "class",
        "status", "state", "active",
        
        # Date/time
        "date", "year", "month", "day", "from_date", "to_date",
    })
    
    @property
    def name(self) -> str:
        return "sqli"
    
    @property
    def description(self) -> str:
        return "Detect SQLi-prone parameters"
    
    @property
    def output_filename(self) -> str:
        return "sqli_candidates.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL has SQLi-prone parameters."""
        return bool(parsed.param_keys_lower & self.SQLI_PARAMS)
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract SQLi param details."""
        found = parsed.param_keys_lower & self.SQLI_PARAMS
        if found:
            # Categorize params
            categories = set()
            if found & {"id", "uid", "userid", "pid", "cid", "item_id"}:
                categories.add("identifier")
            if found & {"search", "query", "q", "keyword", "filter"}:
                categories.add("search")
            if found & {"sort", "sortby", "order", "orderby", "dir"}:
                categories.add("sorting")
            
            return {
                "sqli_params": list(found),
                "categories": list(categories) or ["general"],
            }
        return None
