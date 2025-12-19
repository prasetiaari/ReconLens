# reconlens/core/types.py
"""
Type definitions for ReconLens.

All core dataclasses and type aliases are defined here.
These types are immutable where possible to prevent accidental mutation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, FrozenSet


class RiskLevel(Enum):
    """Risk classification levels for URLs."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class ParsedURL:
    """
    Immutable parsed URL representation.
    
    Attributes:
        raw: Original URL string
        scheme: http or https
        host: Lowercase hostname
        port: Port number (None if default 80/443)
        path: Normalized path starting with /
        query: Raw query string
        fragment: URL fragment (after #)
        params: Parsed query parameters {name: [values]}
    """
    raw: str
    scheme: str = ""
    host: str = ""
    port: Optional[int] = None
    path: str = "/"
    query: str = ""
    fragment: Optional[str] = None
    params: Dict[str, List[str]] = field(default_factory=dict)
    
    @property
    def is_valid(self) -> bool:
        """Check if URL was parsed successfully."""
        return bool(self.host and self.scheme)
    
    @property
    def netloc(self) -> str:
        """Reconstruct netloc (host:port)."""
        if self.port:
            return f"{self.host}:{self.port}"
        return self.host
    
    @property
    def param_keys(self) -> FrozenSet[str]:
        """Get all parameter names as frozen set."""
        return frozenset(self.params.keys())
    
    @property
    def param_keys_lower(self) -> FrozenSet[str]:
        """Get all parameter names in lowercase."""
        return frozenset(k.lower() for k in self.params.keys())


@dataclass
class Target:
    """
    Target scope definition.
    
    Attributes:
        scope: Root domain (e.g., "example.com")
        include_external: If True, include URLs outside scope
        allow_subdomains: Glob patterns to explicitly allow
        deny_subdomains: Glob patterns to explicitly deny
    """
    scope: str
    include_external: bool = False
    allow_subdomains: List[str] = field(default_factory=list)
    deny_subdomains: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        # Normalize scope to lowercase
        self.scope = self.scope.lower().strip()


@dataclass
class AnalysisResult:
    """
    Result from any analyzer module.
    
    Attributes:
        analyzer_name: Name of the analyzer that produced this
        matched_urls: Set of URLs that matched criteria
        total_processed: Total URLs analyzed
        metadata: Additional analyzer-specific data
    """
    analyzer_name: str
    matched_urls: Set[str] = field(default_factory=set)
    total_processed: int = 0
    metadata: Dict = field(default_factory=dict)
    
    @property
    def match_count(self) -> int:
        return len(self.matched_urls)
    
    @property
    def output_filename(self) -> str:
        """Default output filename for this result."""
        return f"{self.analyzer_name}.txt"


@dataclass
class ProbeResult:
    """
    Result from HTTP probing a URL or host.
    
    Attributes:
        url: Probed URL
        host: Hostname
        alive: Whether the host responded
        status_code: HTTP status code
        content_type: Content-Type header
        size: Response size in bytes
        title: Extracted page title
        ips: Resolved IP addresses
        duration_ms: Request duration in milliseconds
        error: Error message if failed
        timestamp: ISO timestamp of probe
    """
    url: str
    host: str
    alive: bool = False
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    size: Optional[int] = None
    title: Optional[str] = None
    ips: List[str] = field(default_factory=list)
    duration_ms: int = 0
    error: Optional[str] = None
    timestamp: Optional[str] = None
    
    @property
    def is_success(self) -> bool:
        """Check if probe was successful (2xx status)."""
        return self.alive and self.status_code is not None and 200 <= self.status_code < 300


@dataclass
class ClassificationResult:
    """
    AI classification result for a URL.
    
    Attributes:
        url: Classified URL
        risk: Risk level
        reason: Explanation for classification
        source: Classification source (e.g., "llm", "rules")
    """
    url: str
    risk: RiskLevel
    reason: str = ""
    source: str = "rules"
