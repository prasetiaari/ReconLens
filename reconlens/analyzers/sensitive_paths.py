# reconlens/analyzers/sensitive_paths.py
"""
Sensitive Paths analyzer.

Detects URLs containing admin, login, debug, and configuration paths
that may expose sensitive functionality.
"""

from __future__ import annotations

from reconlens.analyzers.base import BaseAnalyzer
from reconlens.analyzers import register
from reconlens.core.types import ParsedURL


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
    
    # Paths that indicate sensitive functionality
    SENSITIVE_PATTERNS = frozenset({
        # Admin panels
        "/admin", "/admin/", "/administrator", "/panel", "/panel/",
        "/controlpanel", "/cp", "/dashboard", "/manage", "/management",
        "/backend", "/internal", "/console",
        
        # Authentication
        "/login", "/signin", "/logon", "/user/login", "/users/sign_in",
        "/logout", "/signout", "/register", "/signup",
        
        # WordPress
        "/wp-admin/", "/wp-login.php", "/wp-json/",
        
        # Database tools
        "/phpmyadmin", "/phpmyadmin/", "/adminer", "/adminer.php",
        "/pma", "/mysql", "/pgadmin",
        
        # API docs
        "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml", "/api-docs", "/redoc",
        
        # GraphQL
        "/graphql", "/graphiql", "/playground", "/altair",
        
        # Spring Actuator
        "/actuator", "/actuator/env", "/actuator/health",
        "/actuator/loggers", "/actuator/heapdump",
        
        # CI/CD
        "/jenkins", "/jenkins/", "/script", "/scriptText",
        "/.github/", "/.gitlab-ci.yml",
        
        # Monitoring
        "/grafana", "/grafana/login", "/prometheus", "/metrics",
        "/kibana", "/_plugin/kibana", "/_cat/indices",
        "/_cluster/health", "/jaeger",
        
        # Debug
        "/debug", "/debug/", "/phpinfo", "/info.php", "/test.php",
        "/server-status", "/server-info",
        
        # Config
        "/config", "/settings", "/env", "/.env",
        "/web.config", "/applicationContext.xml",
    })
    
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
        
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in path_lower:
                return True
        
        return False
