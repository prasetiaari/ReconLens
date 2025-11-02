"""
Utility functions for host and URL normalization across ReconLens.
Separated from routers to avoid circular imports.
"""

import re
from urllib.parse import urlparse


_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def normalize_host(val: str) -> str:
    """Accept hostname or URL → return clean hostname (lowercase, no port, no auth)."""
    s = (val or "").strip()
    if not s:
        return ""
    try:
        if "://" in s:
            netloc = urlparse(s).netloc
            s = netloc or s
    except Exception:
        pass
    s = s.lower().strip(".")
    if "@" in s:
        s = s.rsplit("@", 1)[-1]
    if ":" in s:
        s = s.split(":", 1)[0]
    return s


def host_in_scope(host: str, scope: str) -> bool:
    """Return True if host is equal to or subdomain of scope."""
    h = normalize_host(host)
    sc = (scope or "").lower().lstrip(".")
    if not h or not sc:
        return False
    return h == sc or h.endswith("." + sc)