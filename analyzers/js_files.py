# analyzers/js_files.py
"""
JavaScript Files analyzer.

Detects JavaScript file URLs for secrets hunting and source code analysis.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL
from core.url_utils import get_extension


@register
class JSFilesAnalyzer(BaseAnalyzer):
    """
    Detect JavaScript file URLs.
    
    Matches URLs with:
    - .js extension
    - Common JS file patterns
    
    Useful for:
    - Secrets hunting (API keys, tokens)
    - Source code analysis
    - Finding hidden endpoints
    """
    
    # JS-related extensions
    JS_EXTENSIONS = frozenset({
        "js", "mjs", "cjs", "jsx", "ts", "tsx",
    })
    
    # Source map extensions (bonus)
    MAP_EXTENSIONS = frozenset({
        "map", "js.map",
    })
    
    @property
    def name(self) -> str:
        return "js_files"
    
    @property
    def description(self) -> str:
        return "Detect JavaScript files for secrets hunting"
    
    @property
    def output_filename(self) -> str:
        return "js_files.txt"
    
    @property
    def skip_static_assets(self) -> bool:
        """Don't skip - we're specifically looking for JS files."""
        return False
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL points to a JavaScript file."""
        ext = get_extension(parsed.path)
        if not ext:
            return False
        
        return ext in self.JS_EXTENSIONS or ext in self.MAP_EXTENSIONS
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract JS file details."""
        ext = get_extension(parsed.path)
        
        # Extract filename
        filename = parsed.path.rsplit("/", 1)[-1] if "/" in parsed.path else parsed.path
        
        # Check for common patterns
        is_minified = ".min." in filename or filename.endswith(".min.js")
        is_bundle = "bundle" in filename.lower() or "chunk" in filename.lower()
        is_vendor = "vendor" in filename.lower() or "node_modules" in parsed.path
        is_source_map = ext in self.MAP_EXTENSIONS or ext == "map"
        
        return {
            "filename": filename,
            "extension": ext,
            "is_minified": is_minified,
            "is_bundle": is_bundle,
            "is_vendor": is_vendor,
            "is_source_map": is_source_map,
        }
