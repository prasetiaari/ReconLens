# analyzers/lfi.py
"""
LFI (Local File Inclusion) Candidates analyzer.

Detects URLs with parameters commonly used in file inclusion attacks.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class LFIAnalyzer(BaseAnalyzer):
    """
    Detect URLs with LFI/RFI-prone parameters.
    
    Matches URLs containing parameters commonly used in:
    - Local File Inclusion (LFI)
    - Remote File Inclusion (RFI)
    - Path traversal attacks
    """
    
    # Parameters commonly used in file inclusion
    LFI_PARAMS = frozenset({
        # File parameters
        "file", "filename", "filepath", "path", "pathname",
        "document", "doc", "folder", "root", "directory",
        
        # Include parameters
        "include", "inc", "require", "import",
        "page", "pg", "template", "tpl", "layout",
        
        # Read parameters
        "read", "load", "open", "view", "show",
        "display", "content", "data", "source",
        
        # Log/config
        "log", "logs", "logfile", "conf", "config",
        "cfg", "settings", "env",
        
        # Language/locale
        "lang", "language", "locale", "dir",
        
        # Style/skin
        "style", "stylesheet", "css", "theme", "skin",
    })
    
    # Suspicious value patterns
    SUSPICIOUS_VALUES = [
        "../", "..\\",  # Path traversal
        "/etc/", "c:\\",  # System paths
        ".php", ".asp", ".jsp",  # Scripts
        ".log", ".conf", ".ini",  # Config files
    ]
    
    @property
    def name(self) -> str:
        return "lfi"
    
    @property
    def description(self) -> str:
        return "Detect LFI/RFI-prone parameters"
    
    @property
    def output_filename(self) -> str:
        return "lfi_candidates.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL has LFI-prone parameters."""
        return bool(parsed.param_keys_lower & self.LFI_PARAMS)
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract LFI param details."""
        found = parsed.param_keys_lower & self.LFI_PARAMS
        if found:
            # Check for suspicious values
            has_traversal = False
            has_system_path = False
            
            for key in found:
                for k, values in parsed.params.items():
                    if k.lower() == key:
                        for v in values:
                            v_lower = v.lower()
                            if "../" in v or "..\\" in v:
                                has_traversal = True
                            if any(p in v_lower for p in ["/etc/", "c:\\", "/var/"]):
                                has_system_path = True
            
            return {
                "lfi_params": list(found),
                "has_traversal": has_traversal,
                "has_system_path": has_system_path,
            }
        return None
