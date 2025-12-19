# analyzers/backup_files.py
"""
Backup Files analyzer.

Detects URLs pointing to backup, old, or temporary files that
may expose sensitive data or source code.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL
from core.url_utils import get_extension


@register
class BackupFilesAnalyzer(BaseAnalyzer):
    """
    Detect backup and temporary file URLs.
    
    Matches URLs with:
    - Backup extensions (.bak, .old, .backup)
    - Temp files (.tmp, .temp, .swp)
    - Version control leftovers (.git)
    
    These files may expose:
    - Source code
    - Configuration files
    - Database dumps
    """
    
    # Backup/temp extensions
    BACKUP_EXTENSIONS = frozenset({
        # Backups
        "bak", "backup", "back", "old", "orig", "original",
        "save", "sav", "copy", "bkp",
        
        # Temp files
        "tmp", "temp", "swp", "swo", "swn",
        
        # Editor leftovers
        "~", "bck",
        
        # Archives that might be backups
        "tar", "gz", "tgz", "zip", "rar", "7z",
    })
    
    # Suspicious path patterns
    BACKUP_PATTERNS = frozenset({
        ".git/", ".svn/", ".hg/",
        "backup/", "backups/", "bak/",
        "old/", "archive/", "dump/",
    })
    
    @property
    def name(self) -> str:
        return "backup_files"
    
    @property
    def description(self) -> str:
        return "Detect backup and temporary files"
    
    @property
    def output_filename(self) -> str:
        return "backup_files.txt"
    
    @property
    def skip_static_assets(self) -> bool:
        return False
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL points to a backup file."""
        path_lower = parsed.path.lower()
        
        # Check extension
        ext = get_extension(parsed.path)
        if ext and ext in self.BACKUP_EXTENSIONS:
            return True
        
        # Check patterns in path
        for pattern in self.BACKUP_PATTERNS:
            if pattern in path_lower:
                return True
        
        # Check for common backup naming patterns
        filename = path_lower.rsplit("/", 1)[-1]
        if filename.endswith("~"):
            return True
        if filename.startswith(".") and filename.endswith(".swp"):
            return True
        if "_backup" in filename or "_bak" in filename:
            return True
        if "-old" in filename or ".old" in filename:
            return True
        
        return False
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract backup file details."""
        path_lower = parsed.path.lower()
        ext = get_extension(parsed.path)
        
        backup_type = "unknown"
        if ext in {"bak", "backup", "back", "old", "orig"}:
            backup_type = "backup"
        elif ext in {"tmp", "temp", "swp", "swo"}:
            backup_type = "temp"
        elif ext in {"tar", "gz", "tgz", "zip"}:
            backup_type = "archive"
        elif ".git/" in path_lower:
            backup_type = "git"
        elif ".svn/" in path_lower:
            backup_type = "svn"
        
        return {
            "extension": ext,
            "backup_type": backup_type,
        }
