# reconlens/core/scope.py
"""
Scope checking utilities.

Pure functions for determining if a host/URL is within target scope.
No side effects, no I/O operations.
"""

from __future__ import annotations

from fnmatch import fnmatch
from typing import Iterable, Optional

from reconlens.core.types import Target


def host_in_root_scope(host: str, root_domain: str) -> bool:
    """
    Check if host is the root domain or a subdomain of it.
    
    Args:
        host: Hostname to check (e.g., "api.example.com")
        root_domain: Root domain (e.g., "example.com")
        
    Returns:
        True if host is root or subdomain
        
    Examples:
        >>> host_in_root_scope("example.com", "example.com")
        True
        >>> host_in_root_scope("api.example.com", "example.com")
        True
        >>> host_in_root_scope("evil.com", "example.com")
        False
    """
    host = (host or "").lower().rstrip(".")
    root = (root_domain or "").lower().rstrip(".")
    
    if not host or not root:
        return False
    
    return host == root or host.endswith("." + root)


def matches_glob_pattern(host: str, patterns: Iterable[str]) -> bool:
    """
    Check if host matches any glob pattern.
    
    Args:
        host: Hostname to check
        patterns: Glob patterns (e.g., ["*.api.example.com", "admin.*"])
        
    Returns:
        True if host matches any pattern
    """
    host_lower = (host or "").lower()
    
    for pattern in patterns or []:
        if fnmatch(host_lower, pattern.lower()):
            return True
    
    return False


def is_in_scope(
    host: str,
    root_domain: str,
    allow_subdomains: Optional[Iterable[str]] = None,
    deny_subdomains: Optional[Iterable[str]] = None,
) -> bool:
    """
    Evaluate if host is within target scope.
    
    Evaluation order:
    1. If allow_subdomains provided and host matches -> True
    2. If deny_subdomains provided and host matches -> False  
    3. Check if host is root domain or subdomain -> True/False
    
    Args:
        host: Hostname to check
        root_domain: Root domain of target scope
        allow_subdomains: Glob patterns to explicitly allow
        deny_subdomains: Glob patterns to explicitly deny
        
    Returns:
        True if host is in scope
        
    Examples:
        >>> is_in_scope("api.example.com", "example.com")
        True
        >>> is_in_scope("evil.com", "example.com")
        False
        >>> is_in_scope("cdn.external.com", "example.com", 
        ...             allow_subdomains=["*.external.com"])
        True
    """
    # Allow list takes priority
    if allow_subdomains and matches_glob_pattern(host, allow_subdomains):
        return True
    
    # Check deny list
    if deny_subdomains and matches_glob_pattern(host, deny_subdomains):
        return False
    
    # Default: check root scope
    return host_in_root_scope(host, root_domain)


def is_in_target_scope(host: str, target: Target) -> bool:
    """
    Check if host is within Target scope.
    
    Convenience wrapper around is_in_scope using Target object.
    
    Args:
        host: Hostname to check
        target: Target configuration
        
    Returns:
        True if host is in scope (or include_external is True)
    """
    if target.include_external:
        return True
    
    return is_in_scope(
        host=host,
        root_domain=target.scope,
        allow_subdomains=target.allow_subdomains or None,
        deny_subdomains=target.deny_subdomains or None,
    )
