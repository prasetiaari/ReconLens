# reconlens/analyzers/jwt.py
"""
JWT Candidates analyzer.

Detects URLs containing JWT (JSON Web Token) tokens in paths,
query parameters, or fragments.
"""

from __future__ import annotations

import re
import base64
import json
from typing import Optional

from reconlens.analyzers.base import BaseAnalyzer
from reconlens.analyzers import register
from reconlens.core.types import ParsedURL


# JWT regex patterns
# 3-part: header.payload.signature (JWS)
# 5-part: header.encryptedKey.iv.ciphertext.tag (JWE)
B64URL_SEGMENT = r"[A-Za-z0-9_-]{4,}"
RE_JWS = re.compile(rf"({B64URL_SEGMENT})\.({B64URL_SEGMENT})\.({B64URL_SEGMENT})")
RE_JWE = re.compile(rf"({B64URL_SEGMENT})\.({B64URL_SEGMENT})\.({B64URL_SEGMENT})\.({B64URL_SEGMENT})\.({B64URL_SEGMENT})")


def _b64url_decode(s: str) -> Optional[bytes]:
    """Safely decode base64url string."""
    try:
        # Add padding
        padding = (-len(s)) % 4
        return base64.urlsafe_b64decode(s + ("=" * padding))
    except Exception:
        return None


def _is_jwt_header(segment: str) -> bool:
    """
    Check if segment is a valid JWT header.
    Must decode to JSON with 'alg' key.
    """
    decoded = _b64url_decode(segment)
    if not decoded:
        return False
    
    try:
        obj = json.loads(decoded.decode("utf-8"))
        return isinstance(obj, dict) and "alg" in obj
    except Exception:
        return False


def _contains_jwt(text: str) -> bool:
    """Check if text contains a valid JWT token."""
    if not text or len(text) < 20:  # Minimum reasonable JWT length
        return False
    
    # Try 5-part JWE first
    for match in RE_JWE.finditer(text):
        if _is_jwt_header(match.group(1)):
            return True
    
    # Try 3-part JWS
    for match in RE_JWS.finditer(text):
        if _is_jwt_header(match.group(1)):
            return True
    
    return False


@register
class JWTAnalyzer(BaseAnalyzer):
    """
    Detect URLs containing JWT tokens.
    
    Validates JWT by checking that the first segment decodes
    to JSON with an 'alg' field (reducing false positives).
    """
    
    @property
    def name(self) -> str:
        return "jwt"
    
    @property
    def description(self) -> str:
        return "Detect URLs containing JWT tokens"
    
    @property
    def output_filename(self) -> str:
        return "jwt_candidates.txt"
    
    @property
    def skip_static_assets(self) -> bool:
        """Don't skip static - JWT might be in query params."""
        return False
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL contains a JWT token anywhere."""
        # Check raw URL
        if _contains_jwt(parsed.raw):
            return True
        
        # Check each parameter value
        for values in parsed.params.values():
            for value in values:
                if _contains_jwt(value):
                    return True
        
        # Check fragment
        if parsed.fragment and _contains_jwt(parsed.fragment):
            return True
        
        return False
