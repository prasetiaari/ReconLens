# analyzers/rce.py
"""
RCE (Remote Code Execution) Candidates analyzer.

Detects URLs with parameters commonly used in command execution.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class RCEAnalyzer(BaseAnalyzer):
    """
    Detect URLs with RCE-prone parameters.
    
    Matches URLs with command/code execution parameters.
    """
    
    # Parameters commonly used in command execution
    RCE_PARAMS = frozenset({
        # Command
        "cmd", "command", "exec", "execute", "run",
        "shell", "sh", "bash", "powershell", "ps",
        
        # Code
        "code", "eval", "expression", "expr", "query",
        
        # Process
        "process", "spawn", "proc", "program", "app",
        
        # System
        "system", "sys", "ping", "nslookup", "dig",
        "traceroute", "curl", "wget",
        
        # Script
        "script", "payload", "data", "input",
        
        # Deserialize
        "object", "serialize", "json", "xml", "pickle",
    })
    
    @property
    def name(self) -> str:
        return "rce"
    
    @property
    def description(self) -> str:
        return "Detect RCE-prone command execution parameters"
    
    @property
    def output_filename(self) -> str:
        return "rce_candidates.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL has RCE-prone parameters."""
        return bool(parsed.param_keys_lower & self.RCE_PARAMS)
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract RCE param details."""
        found = parsed.param_keys_lower & self.RCE_PARAMS
        if found:
            return {"rce_params": list(found)}
        return None
