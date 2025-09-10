# app/services/ui_utils.py
from __future__ import annotations
from datetime import datetime, timezone

UNITS = ["B", "KB", "MB", "GB", "TB"]

def humansize(n: int | float | None) -> str:
    if n is None:
        return "-"
    try:
        n = float(n)
    except Exception:
        return str(n)
    i = 0
    while n >= 1024 and i < len(UNITS) - 1:
        n /= 1024.0
        i += 1
    if i == 0:
        return f"{int(n)} {UNITS[i]}"
    return f"{n:.1f} {UNITS[i]}"

def timeago(ts: int | float | None) -> str:
    """ts = UNIX epoch (seconds). Return e.g. '2m ago'."""
    if not ts:
        return "-"
    now = datetime.now(timezone.utc).timestamp()
    delta = max(0, int(now - int(ts)))
    if delta < 60:
        return f"{delta}s ago"
    mins = delta // 60
    if mins < 60:
        return f"{mins}m ago"
    hrs = mins // 60
    if hrs < 24:
        return f"{hrs}h ago"
    days = hrs // 24
    if days < 30:
        return f"{days}d ago"
    months = days // 30
    if months < 12:
        return f"{months}mo ago"
    years = months // 12
    return f"{years}y ago"
