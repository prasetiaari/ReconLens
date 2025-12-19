# analyzers/upload.py
"""
File Upload Endpoints analyzer.

Detects URLs that appear to handle file uploads.
"""

from __future__ import annotations

import re
from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class UploadAnalyzer(BaseAnalyzer):
    """
    Detect file upload endpoints.
    
    Matches URLs with upload-related paths or parameters.
    """
    
    # Path patterns for uploads
    UPLOAD_PATH_PATTERNS = [
        r"/upload",
        r"/uploads",
        r"/file-upload",
        r"/file_upload",
        r"/attachment",
        r"/attachments",
        r"/media",
        r"/import",
        r"/submit",
        r"/post",
    ]
    
    RE_UPLOAD_PATTERNS = [re.compile(p, re.I) for p in UPLOAD_PATH_PATTERNS]
    
    # Upload-related params
    UPLOAD_PARAMS = frozenset({
        "file", "files", "upload", "attachment", "attachments",
        "document", "doc", "image", "images", "photo", "photos",
        "media", "avatar", "picture", "icon", "logo",
        "import", "csv", "excel", "pdf",
    })
    
    @property
    def name(self) -> str:
        return "upload"
    
    @property
    def description(self) -> str:
        return "Detect file upload endpoints"
    
    @property
    def output_filename(self) -> str:
        return "upload_endpoints.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL is an upload endpoint."""
        # Check path patterns
        for pattern in self.RE_UPLOAD_PATTERNS:
            if pattern.search(parsed.path):
                return True
        
        # Check params
        if parsed.param_keys_lower & self.UPLOAD_PARAMS:
            return True
        
        return False
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract upload details."""
        found_params = parsed.param_keys_lower & self.UPLOAD_PARAMS
        return {
            "upload_params": list(found_params) if found_params else [],
            "has_upload_path": any(p.search(parsed.path) for p in self.RE_UPLOAD_PATTERNS),
        }
