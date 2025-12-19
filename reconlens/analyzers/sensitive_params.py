# reconlens/analyzers/sensitive_params.py
"""
Sensitive Parameters analyzer.

Detects URLs containing query parameters that may leak
sensitive information like passwords, tokens, API keys, etc.
"""

from __future__ import annotations

from reconlens.analyzers.base import BaseAnalyzer
from reconlens.analyzers import register
from reconlens.core.types import ParsedURL


@register
class SensitiveParamsAnalyzer(BaseAnalyzer):
    """
    Detect URLs with sensitive query parameters.
    
    Matches URLs containing parameters that commonly hold
    sensitive data (passwords, tokens, keys, etc.)
    """
    
    # Parameters that commonly hold sensitive values
    SENSITIVE_PARAMS = frozenset({
        # Authentication
        "password", "passwd", "pwd", "pass", "secret",
        "token", "access_token", "refresh_token", "auth_token",
        "session", "sessionid", "session_id", "sid",
        "jwt", "bearer", "authorization", "auth",
        
        # API keys
        "api_key", "apikey", "api-key", "key",
        "api_secret", "apisecret", "client_secret",
        "app_key", "appkey", "app_secret", "appsecret",
        
        # OAuth
        "client_id", "client_secret", "code", "grant_type",
        "oauth_token", "oauth_verifier",
        
        # Database/connection strings
        "connection", "connectionstring", "conn", "dsn",
        "db_password", "db_user", "database",
        
        # Encryption
        "private_key", "privatekey", "encryption_key",
        "signing_key", "hmac", "salt",
        
        # Credentials
        "username", "user", "login", "email", "mail",
        "account", "credential", "credentials",
        
        # Payment
        "credit_card", "cc", "cvv", "card_number",
        "account_number", "routing_number",
        
        # Debug/internal
        "debug", "test", "internal", "admin",
    })
    
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
        return bool(parsed.param_keys_lower & self.SENSITIVE_PARAMS)
