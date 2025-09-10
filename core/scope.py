# urls_parser/core/scope.py
from __future__ import annotations

from fnmatch import fnmatch
from typing import Iterable, Optional

def host_in_root_scope(host: str, root_domain: str) -> bool:
    """True jika host == root_domain atau subdomain-nya."""
    host = (host or "").lower().rstrip(".")
    root = (root_domain or "").lower().rstrip(".")
    if not host or not root:
        return False
    return host == root or host.endswith("." + root)

def matches_any(host: str, patterns: Iterable[str]) -> bool:
    """Cek glob/wildcard patterns seperti '*.api.example.com'."""
    h = (host or "").lower()
    for pat in patterns or []:
        if fnmatch(h, pat.lower()):
            return True
    return False

def is_in_scope(
    host: str,
    root_domain: str,
    allow_subdomains: Optional[Iterable[str]] = None,
    deny_subdomains: Optional[Iterable[str]] = None,
) -> bool:
    """Evaluasi scope dengan urutan: allow > deny > root-scope."""
    if allow_subdomains:
        return matches_any(host, allow_subdomains)
    if deny_subdomains and matches_any(host, deny_subdomains):
        return False
    return host_in_root_scope(host, root_domain)
