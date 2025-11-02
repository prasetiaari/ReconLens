"""
Jinja2 custom filters used across ReconLens templates.
This module provides reusable utilities for human-readable
size formatting and relative time display.
"""

from datetime import datetime, timezone
from dateutil import parser as dtparser


def humansize(n):
    """
    Convert a number of bytes into a human-readable size string.
    Examples:
        123 -> "123 B"
        2048 -> "2.0 KB"
        5242880 -> "5.0 MB"
    """
    if n is None:
        return "-"
    try:
        n = float(n)
    except Exception:
        return "-"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.0f} {units[i]}" if i == 0 else f"{n:.1f} {units[i]}"


def timeago(iso_str: str):
    """
    Return a human-readable "time ago" string for an ISO timestamp.
    Example: "2025-11-02T12:00:00Z" -> "3h ago"
    """
    try:
        t = dtparser.isoparse(iso_str)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        sec = int((now - t).total_seconds())
        if sec < 60:
            return f"{sec}s ago"
        mins = sec // 60
        if mins < 60:
            return f"{mins}m ago"
        hrs = mins // 60
        if hrs < 24:
            return f"{hrs}h ago"
        days = hrs // 24
        return f"{days}d ago"
    except Exception:
        return iso_str


__all__ = ["humansize", "timeago"]