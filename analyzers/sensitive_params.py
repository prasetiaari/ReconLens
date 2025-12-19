# analyzers/sensitive_params.py
"""
Sensitive Parameters analyzer.

Detects URLs containing query parameters that may leak
sensitive information like passwords, tokens, API keys, etc.
"""

from __future__ import annotations

from typing import Dict, Any, Optional, List

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class SensitiveParamsAnalyzer(BaseAnalyzer):
    """
    Detect URLs with sensitive query parameters.
    
    Matches URLs containing parameters that commonly hold
    sensitive data (passwords, tokens, keys, etc.)
    """
    
    # Categorized sensitive parameters
    PARAMS = {
        "auth": [
            "password", "passwd", "pwd", "pass", "secret",
            "token", "access_token", "refresh_token", "auth_token",
            "session", "sessionid", "session_id", "sid",
            "jwt", "bearer", "authorization", "auth",
        ],
        "api_keys": [
            "api_key", "apikey", "api-key", "key",
            "api_secret", "apisecret", "client_secret",
            "app_key", "appkey", "app_secret", "appsecret",
            "secret_key", "secretkey", "access_key", "accesskey",
        ],
        "oauth": [
            "client_id", "client_secret", "code", "grant_type",
            "oauth_token", "oauth_verifier", "state", "nonce",
        ],
        "database": [
            "connection", "connectionstring", "conn", "dsn",
            "db_password", "db_user", "database", "host",
        ],
        "encryption": [
            "private_key", "privatekey", "encryption_key",
            "signing_key", "hmac", "salt", "iv", "nonce",
        ],
        "credentials": [
            "username", "user", "login", "email", "mail",
            "account", "credential", "credentials",
        ],
        "payment": [
            "credit_card", "cc", "cvv", "card_number",
            "account_number", "routing_number", "pin",
        ],
        "debug": [
            "debug", "test", "internal", "admin", "verbose",
        ],
    }
    
    # Flattened set for fast lookup
    ALL_PARAMS = frozenset(
        param
        for params in PARAMS.values()
        for param in params
    )
    
    @property
    def name(self) -> str:
        return "sensitive_params"
    
    @property
    def description(self) -> str:
        return "Detect URLs with sensitive query parameters"
    
    @property
    def output_filename(self) -> str:
        return "sensitive_params.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL has any sensitive parameters."""
        return bool(parsed.param_keys_lower & self.ALL_PARAMS)
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract categories and found params."""
        found_params = parsed.param_keys_lower & self.ALL_PARAMS
        
        if found_params:
            # Determine categories
            categories: List[str] = []
            for category, params in self.PARAMS.items():
                if any(p in found_params for p in params):
                    categories.append(category)
            
            return {
                "params": list(found_params),
                "categories": categories,
            }
        return None
