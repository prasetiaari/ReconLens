# analyzers/documents.py
"""
Documents analyzer.

Detects URLs pointing to document files that may contain
sensitive information (PDFs, Office docs, databases, backups).
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL
from core.url_utils import get_extension


@register
class DocumentsAnalyzer(BaseAnalyzer):
    """
    Detect URLs pointing to document files.
    
    Matches URLs with file extensions commonly associated with:
    - Documents (PDF, Office, text)
    - Databases and backups
    - Archives
    - Logs and configs
    """
    
    # Categorized file extensions
    EXTENSIONS = {
        "documents": {
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
            "odt", "ods", "odp", "rtf", "txt", "md",
        },
        "database": {
            "sql", "sqlite", "db", "mdb", "accdb",
            "dump", "dmp",
        },
        "backup": {
            "bak", "backup", "old", "orig", "copy",
            "swp", "swo", "tmp", "temp",
        },
        "archive": {
            "zip", "gz", "tar", "rar", "7z", "bz2",
            "tgz", "tbz2", "xz",
        },
        "config": {
            "conf", "cfg", "ini", "yaml", "yml", "toml",
            "properties", "env", "htaccess", "htpasswd",
        },
        "log": {
            "log", "logs", "err", "error", "out",
        },
        "data": {
            "csv", "json", "xml", "tsv",
        },
    }
    
    # Flattened set
    ALL_EXTENSIONS = frozenset(
        ext
        for exts in EXTENSIONS.values()
        for ext in exts
    )
    
    @property
    def name(self) -> str:
        return "documents"
    
    @property
    def description(self) -> str:
        return "Detect URLs pointing to document files"
    
    @property
    def output_filename(self) -> str:
        return "documents.txt"
    
    @property
    def skip_static_assets(self) -> bool:
        """Don't skip - we're specifically looking for files."""
        return False
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL points to a document file."""
        ext = get_extension(parsed.path)
        return ext in self.ALL_EXTENSIONS if ext else False
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract file type category."""
        ext = get_extension(parsed.path)
        if not ext:
            return None
        
        for category, extensions in self.EXTENSIONS.items():
            if ext in extensions:
                return {
                    "extension": ext,
                    "category": category,
                }
        
        return {"extension": ext, "category": "unknown"}
