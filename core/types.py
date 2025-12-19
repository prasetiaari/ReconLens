# core/types.py
"""
Type definitions for ReconLens.

All core dataclasses and type aliases are defined here.
These types are immutable where possible to prevent accidental mutation.

Enterprise-grade features:
- Frozen dataclasses for immutability
- Rich computed properties
- Type hints throughout
- Comprehensive docstrings
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, FrozenSet, Any
from datetime import datetime


class RiskLevel(Enum):
    """Risk classification levels for URLs."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    def __str__(self) -> str:
        return self.value


class ProbeStatus(Enum):
    """Status of HTTP probe."""
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    DNS_ERROR = "dns_error"


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
    
    Example:
        >>> url = parse_url("https://example.com/path?foo=bar")
        >>> url.host
        'example.com'
        >>> url.is_valid
        True
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
    
    @property
    def base_url(self) -> str:
        """URL without query string and fragment."""
        port_str = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{self.host}{port_str}{self.path}"


@dataclass
class Target:
    """
    Target scope definition.
    
    Attributes:
        scope: Root domain (e.g., "example.com")
        include_external: If True, include URLs outside scope
        allow_subdomains: Glob patterns to explicitly allow
        deny_subdomains: Glob patterns to explicitly deny
        metadata: Additional target metadata
    """
    scope: str
    include_external: bool = False
    allow_subdomains: List[str] = field(default_factory=list)
    deny_subdomains: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        # Normalize scope to lowercase
        self.scope = self.scope.lower().strip()
    
    @property
    def display_name(self) -> str:
        """Human-readable target name."""
        return self.metadata.get("name", self.scope)


@dataclass
class AnalysisResult:
    """
    Result from any analyzer module.
    
    Attributes:
        analyzer_name: Name of the analyzer that produced this
        matched_urls: Set of URLs that matched criteria
        total_processed: Total URLs analyzed
        metadata: Additional analyzer-specific data
        timestamp: When analysis was performed
    """
    analyzer_name: str
    matched_urls: Set[str] = field(default_factory=set)
    total_processed: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"
    
    @property
    def match_count(self) -> int:
        return len(self.matched_urls)
    
    @property
    def match_rate(self) -> float:
        """Percentage of URLs that matched."""
        if self.total_processed == 0:
            return 0.0
        return (self.match_count / self.total_processed) * 100
    
    @property
    def output_filename(self) -> str:
        """Default output filename for this result."""
        return f"{self.analyzer_name}.txt"
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "analyzer_name": self.analyzer_name,
            "match_count": self.match_count,
            "total_processed": self.total_processed,
            "match_rate": round(self.match_rate, 2),
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


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
        headers: Response headers (optional)
    """
    url: str
    host: str
    alive: bool = False
    status: ProbeStatus = ProbeStatus.PENDING
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    size: Optional[int] = None
    title: Optional[str] = None
    ips: List[str] = field(default_factory=list)
    duration_ms: int = 0
    error: Optional[str] = None
    timestamp: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    
    @property
    def is_success(self) -> bool:
        """Check if probe was successful (2xx status)."""
        return self.alive and self.status_code is not None and 200 <= self.status_code < 300
    
    @property
    def is_redirect(self) -> bool:
        """Check if response is a redirect (3xx)."""
        return self.status_code is not None and 300 <= self.status_code < 400
    
    @property
    def is_client_error(self) -> bool:
        """Check if response is client error (4xx)."""
        return self.status_code is not None and 400 <= self.status_code < 500
    
    @property
    def is_server_error(self) -> bool:
        """Check if response is server error (5xx)."""
        return self.status_code is not None and 500 <= self.status_code < 600
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "url": self.url,
            "host": self.host,
            "alive": self.alive,
            "status": self.status.value,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "size": self.size,
            "title": self.title,
            "ips": self.ips,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "timestamp": self.timestamp,
        }


@dataclass
class ClassificationResult:
    """
    AI/rule-based classification result for a URL.
    
    Attributes:
        url: Classified URL
        risk: Risk level
        reason: Explanation for classification
        source: Classification source (e.g., "llm", "rules")
        confidence: Confidence score (0.0-1.0)
    """
    url: str
    risk: RiskLevel
    reason: str = ""
    source: str = "rules"
    confidence: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "url": self.url,
            "risk": self.risk.value,
            "reason": self.reason,
            "source": self.source,
            "confidence": self.confidence,
        }


@dataclass
class JobStatus:
    """
    Status of a background job.
    
    Attributes:
        job_id: Unique job identifier
        job_type: Type of job (e.g., "probe", "analyze", "collect")
        status: Current status
        progress: Progress percentage (0-100)
        message: Current status message
        result: Job result when complete
        error: Error message if failed
        started_at: When job started
        completed_at: When job completed
    """
    job_id: str
    job_type: str
    status: str = "pending"  # pending, running, completed, failed
    progress: int = 0
    message: str = ""
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    
    @property
    def is_complete(self) -> bool:
        return self.status in ("completed", "failed")
    
    @property
    def is_success(self) -> bool:
        return self.status == "completed"
