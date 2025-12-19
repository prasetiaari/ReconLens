# analyzers/sensitive_paths.py
"""
Sensitive Paths analyzer.

Detects URLs containing admin, login, debug, and configuration paths
that may expose sensitive functionality.
"""

from __future__ import annotations

from typing import Dict, Any, Optional, List

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class SensitivePathsAnalyzer(BaseAnalyzer):
    """
    Detect URLs with sensitive paths.
    
    Matches URLs containing paths commonly associated with:
    - Admin panels
    - Login pages
    - Debug interfaces
    - Configuration endpoints
    - API documentation
    - Monitoring dashboards
    """
    
    # Categorized sensitive patterns
    PATTERNS = {
        "admin": [
            "/admin", "/admin/", "/administrator", "/panel", "/panel/",
            "/controlpanel", "/cp", "/dashboard", "/manage", "/management",
            "/backend", "/internal", "/console", "/webmaster",
        ],
        "auth": [
            "/login", "/signin", "/logon", "/user/login", "/users/sign_in",
            "/logout", "/signout", "/register", "/signup", "/forgot",
            "/reset-password", "/change-password", "/2fa", "/mfa",
        ],
        "wordpress": [
            "/wp-admin/", "/wp-login.php", "/wp-json/", "/wp-content/",
            "/wp-includes/", "/xmlrpc.php",
        ],
        "database": [
            "/phpmyadmin", "/phpmyadmin/", "/adminer", "/adminer.php",
            "/pma", "/mysql", "/pgadmin", "/mongodb", "/redis",
        ],
        "api_docs": [
            "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
            "/openapi.json", "/openapi.yaml", "/api-docs", "/redoc",
            "/docs", "/documentation",
        ],
        "graphql": [
            "/graphql", "/graphiql", "/playground", "/altair", "/voyager",
        ],
        "spring": [
            "/actuator", "/actuator/env", "/actuator/health",
            "/actuator/loggers", "/actuator/heapdump", "/actuator/beans",
            "/actuator/mappings", "/actuator/configprops",
        ],
        "cicd": [
            "/jenkins", "/jenkins/", "/script", "/scriptText",
            "/.github/", "/.gitlab-ci.yml", "/.travis.yml",
            "/bamboo", "/teamcity", "/circleci",
        ],
        "monitoring": [
            "/grafana", "/grafana/login", "/prometheus", "/metrics",
            "/kibana", "/_plugin/kibana", "/_cat/indices",
            "/_cluster/health", "/jaeger", "/zipkin", "/newrelic",
        ],
        "debug": [
            "/debug", "/debug/", "/phpinfo", "/info.php", "/test.php",
            "/server-status", "/server-info", "/status", "/.well-known/",
            "/trace", "/console", "/shell",
        ],
        "config": [
            "/config", "/settings", "/env", "/.env", "/.env.local",
            "/web.config", "/applicationContext.xml", "/config.php",
            "/config.yml", "/config.json", "/application.properties",
        ],
        "backup": [
            "/backup", "/backups", "/dump", "/export", "/download",
            "/db.sql", "/database.sql", "/.git/", "/.svn/",
        ],
    }
    
    # Flattened set for fast lookup
    ALL_PATTERNS = frozenset(
        pattern 
        for patterns in PATTERNS.values() 
        for pattern in patterns
    )
    
    @property
    def name(self) -> str:
        return "sensitive_paths"
    
    @property
    def description(self) -> str:
        return "Detect URLs with admin, login, debug, and config paths"
    
    @property
    def output_filename(self) -> str:
        return "sensitive_paths.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL path contains any sensitive patterns."""
        path_lower = parsed.path.lower()
        
        for pattern in self.ALL_PATTERNS:
            if pattern in path_lower:
                return True
        
        return False
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract categories and matched patterns."""
        path_lower = parsed.path.lower()
        matched_categories: List[str] = []
        matched_patterns: List[str] = []
        
        for category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if pattern in path_lower:
                    if category not in matched_categories:
                        matched_categories.append(category)
                    matched_patterns.append(pattern)
        
        if matched_categories:
            return {
                "categories": matched_categories,
                "patterns": matched_patterns[:5],  # Limit to first 5
            }
        return None
