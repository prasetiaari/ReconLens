"""
Parsers for Recon Tools Output
------------------------------

This module provides regex-based parsers and data normalization utilities
for external recon tool outputs (e.g., Dirsearch).

All functions are stateless and pure — safe for reuse across routers.
"""

from __future__ import annotations
import re
from typing import Optional, Dict

# ---------------------------------------------------------------------------
# Dirsearch Line Parser
# ---------------------------------------------------------------------------

# Example line:
#   [13:11:00] 200 -  12KB - https://example.com/admin/
#   [13:11:05] 301 -   0B  - https://a/old  ->  https://a/new

_DIR_LINE_RE = re.compile(
    r"\[(\d{2}:\d{2}:\d{2})\]\s+(\d{3})\s*-\s*([0-9.]+\s*[KMG]?B)\s*-\s*(https?://\S+?)(?:\s*->\s*(\S+))?\s*$",
    re.IGNORECASE,
)

def parse_dirsearch_line(line: str) -> Optional[Dict]:
    """
    Parse a single Dirsearch output line into structured data.

    Args:
        line: A string line from Dirsearch output.

    Returns:
        dict with { "code": int, "size": int|None, "url": str, "redirect": str|None }
        or None if the line doesn't match expected pattern.
    """
    m = _DIR_LINE_RE.search(line)
    if not m:
        return None
    _, code_s, size_s, url, redirect = m.groups()
    code = int(code_s)
    size = size_to_bytes(size_s)
    return {"code": code, "size": size, "url": url, "redirect": redirect}


# ---------------------------------------------------------------------------
# Size Conversion Utility
# ---------------------------------------------------------------------------

def size_to_bytes(size_str: str) -> Optional[int]:
    """
    Convert human-readable size (e.g., '1KB', '12.3 MB', '456B') to integer bytes.

    Args:
        size_str: Size string (may include KB, MB, GB suffix).

    Returns:
        Integer bytes, or None if conversion fails.
    """
    if not size_str:
        return None
    s = size_str.strip().upper().replace(" ", "")
    try:
        if s.endswith("KB"):
            return int(float(s[:-2]) * 1024)
        if s.endswith("MB"):
            return int(float(s[:-2]) * 1024 * 1024)
        if s.endswith("GB"):
            return int(float(s[:-2]) * 1024 * 1024 * 1024)
        if s.endswith("B"):
            return int(float(s[:-1]))
        return int(float(s))
    except Exception:
        return None