# analyzers/jwt.py
"""
JWT Candidates analyzer.

Detects URLs containing JWT (JSON Web Token) tokens in paths,
query parameters, or fragments.

Uses proper JWT header validation to minimize false positives.
"""

from __future__ import annotations

import re
import base64
import json
from typing import Optional, Dict, Any

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


# JWT regex patterns
# 3-part: header.payload.signature (JWS)
# 5-part: header.encryptedKey.iv.ciphertext.tag (JWE)
B64URL_SEGMENT = r"[A-Za-z0-9_-]{4,}"
RE_JWS = re.compile(rf"({B64URL_SEGMENT})\.({B64URL_SEGMENT})\.({B64URL_SEGMENT})")
RE_JWE = re.compile(rf"({B64URL_SEGMENT})\.({B64URL_SEGMENT})\.({B64URL_SEGMENT})\.({B64URL_SEGMENT})\.({B64URL_SEGMENT})")


def _b64url_decode(s: str) -> Optional[bytes]:
    """Safely decode base64url string."""
    try:
        padding = (-len(s)) % 4
        return base64.urlsafe_b64decode(s + ("=" * padding))
    except Exception:
        return None


def _parse_jwt_header(segment: str) -> Optional[Dict]:
    """
    Parse JWT header segment.
    Returns header dict if valid, None otherwise.
    """
    decoded = _b64url_decode(segment)
    if not decoded:
        return None
    
    try:
        obj = json.loads(decoded.decode("utf-8"))
        if isinstance(obj, dict) and "alg" in obj:
            return obj
    except Exception:
        pass
    
    return None


def _find_jwt(text: str) -> Optional[Dict[str, Any]]:
    """
    Find JWT token in text.
    Returns token info if found, None otherwise.
    """
    if not text or len(text) < 20:
        return None
    
    # Try 5-part JWE first
    for match in RE_JWE.finditer(text):
        header = _parse_jwt_header(match.group(1))
        if header:
            return {
                "type": "JWE",
                "algorithm": header.get("alg"),
                "encryption": header.get("enc"),
                "token_preview": match.group(0)[:50] + "...",
            }
    
    # Try 3-part JWS
    for match in RE_JWS.finditer(text):
        header = _parse_jwt_header(match.group(1))
        if header:
            return {
                "type": "JWS",
                "algorithm": header.get("alg"),
                "token_preview": match.group(0)[:50] + "...",
            }
    
    return None


@register
class JWTAnalyzer(BaseAnalyzer):
    """
    Detect URLs containing JWT tokens.
    
    Validates JWT by checking that the first segment decodes
    to JSON with an 'alg' field (reducing false positives from
    version strings like 'jquery.1.2.3').
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
        if _find_jwt(parsed.raw):
            return True
        
        # Check each parameter value
        for values in parsed.params.values():
            for value in values:
                if _find_jwt(value):
                    return True
        
        # Check fragment
        if parsed.fragment and _find_jwt(parsed.fragment):
            return True
        
        return False
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract JWT details."""
        # Check raw URL first
        jwt_info = _find_jwt(parsed.raw)
        if jwt_info:
            return jwt_info
        
        # Check params
        for key, values in parsed.params.items():
            for value in values:
                jwt_info = _find_jwt(value)
                if jwt_info:
                    jwt_info["param_name"] = key
                    return jwt_info
        
        # Check fragment
        if parsed.fragment:
            jwt_info = _find_jwt(parsed.fragment)
            if jwt_info:
                jwt_info["location"] = "fragment"
                return jwt_info
        
        return None
