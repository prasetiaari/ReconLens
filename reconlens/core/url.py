# reconlens/core/url.py
"""
URL parsing utilities.

Pure functions for parsing and normalizing URLs.
No side effects, no I/O operations.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, unquote_plus

from reconlens.core.types import ParsedURL


# --- Constants ---

STATIC_EXTENSIONS = frozenset({
    # Images
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "tiff",
    # Fonts
    "woff", "woff2", "ttf", "otf", "eot",
    # Styles & Scripts
    "css", "js", "map",
    # Media
    "mp4", "webm", "mov", "avi", "mp3", "wav", "flac", "ogg",
})

DEFAULT_PORTS = {"http": 80, "https": 443}
HTTP_SCHEMES = frozenset({"http", "https"})


# --- Internal helpers ---

def _normalize_host(host: Optional[str]) -> str:
    """Lowercase and strip trailing dots from host."""
    if not host:
        return ""
    return host.lower().rstrip(".")


def _extract_host_port(netloc: str, scheme: str) -> Tuple[str, Optional[int]]:
    """
    Extract host and port from netloc.
    Removes default ports (80 for http, 443 for https).
    """
    host = netloc
    port: Optional[int] = None

    # Handle IPv6: [::1]:8080
    if host.startswith("["):
        if "]" in host:
            bracket_end = host.rfind("]")
            host_part = host[:bracket_end + 1]
            rest = host[bracket_end + 1:]
            if rest.startswith(":"):
                try:
                    port = int(rest[1:])
                except ValueError:
                    port = None
            host = host_part
    else:
        # Regular host:port
        if ":" in host:
            host_part, port_part = host.rsplit(":", 1)
            host = host_part
            try:
                port = int(port_part)
            except ValueError:
                port = None

    host = _normalize_host(host)
    
    # Remove default ports
    if port is not None and scheme in DEFAULT_PORTS:
        if port == DEFAULT_PORTS[scheme]:
            port = None
    
    return host, port


def _normalize_path(path: str) -> str:
    """
    Normalize URL path:
    - Ensure leading slash
    - Compress multiple slashes
    - Does NOT resolve '..' to preserve historical URL semantics
    """
    if not path:
        return "/"
    if not path.startswith("/"):
        path = "/" + path
    # Compress multiple slashes
    path = re.sub(r"/{2,}", "/", path)
    return path


def _parse_query_params(query: str) -> Dict[str, List[str]]:
    """
    Parse query string to dict.
    Preserves duplicate parameters as list of values.
    """
    params: Dict[str, List[str]] = {}
    if not query:
        return params
    
    for key, value in parse_qsl(query, keep_blank_values=True):
        key = key.strip()
        if key in params:
            params[key].append(value)
        else:
            params[key] = [value]
    
    return params


# --- Public API ---

def parse_url(url_raw: str) -> ParsedURL:
    """
    Parse a raw URL string into a ParsedURL object.
    
    Only supports http/https URLs. Returns ParsedURL with is_valid=False
    for invalid or non-HTTP URLs.
    
    Args:
        url_raw: Raw URL string
        
    Returns:
        ParsedURL: Parsed and normalized URL data
    
    Example:
        >>> url = parse_url("https://example.com/path?foo=bar")
        >>> url.host
        'example.com'
        >>> url.params
        {'foo': ['bar']}
    """
    url_raw = (url_raw or "").strip()
    
    if not url_raw:
        return ParsedURL(raw=url_raw)
    
    try:
        parsed = urlparse(url_raw)
    except Exception:
        return ParsedURL(raw=url_raw)
    
    # Only support HTTP/HTTPS
    if parsed.scheme not in HTTP_SCHEMES or not parsed.netloc:
        return ParsedURL(raw=url_raw)
    
    host, port = _extract_host_port(parsed.netloc, parsed.scheme)
    path = _normalize_path(unquote_plus(parsed.path or "/"))
    query = parsed.query or ""
    fragment = parsed.fragment or None
    params = _parse_query_params(query)
    
    return ParsedURL(
        raw=url_raw,
        scheme=parsed.scheme,
        host=host,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        params=params,
    )


def get_extension(path: str) -> Optional[str]:
    """
    Extract file extension from path.
    
    Args:
        path: URL path
        
    Returns:
        Lowercase extension without dot, or None
    """
    if "." not in path:
        return None
    
    filename = path.rsplit("/", 1)[-1]
    if "." not in filename:
        return None
    
    ext = filename.rsplit(".", 1)[-1].lower()
    return ext if ext else None


def is_static_asset(path: str) -> bool:
    """
    Check if path points to a static asset (image, css, js, etc).
    
    Args:
        path: URL path
        
    Returns:
        True if path has a static asset extension
    """
    ext = get_extension(path)
    return ext in STATIC_EXTENSIONS if ext else False


def decode_percent(s: str) -> str:
    """
    Decode percent-encoded string once.
    
    Args:
        s: Encoded string
        
    Returns:
        Decoded string
    """
    try:
        return unquote_plus(s)
    except Exception:
        return s
