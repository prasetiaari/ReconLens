# tests/test_core/test_types.py
"""
Tests for core type definitions.
"""

import pytest
from core.types import ParsedURL, Target, AnalysisResult, ProbeResult, RiskLevel


class TestParsedURL:
    """Tests for ParsedURL dataclass."""
    
    def test_is_valid_with_host(self):
        url = ParsedURL(raw="https://example.com", scheme="https", host="example.com")
        assert url.is_valid is True
    
    def test_is_valid_without_host(self):
        url = ParsedURL(raw="invalid")
        assert url.is_valid is False
    
    def test_netloc_with_port(self):
        url = ParsedURL(raw="https://example.com:8080", scheme="https", host="example.com", port=8080)
        assert url.netloc == "example.com:8080"
    
    def test_netloc_without_port(self):
        url = ParsedURL(raw="https://example.com", scheme="https", host="example.com")
        assert url.netloc == "example.com"
    
    def test_param_keys(self):
        url = ParsedURL(
            raw="https://example.com?foo=1&bar=2",
            scheme="https",
            host="example.com",
            params={"foo": ["1"], "Bar": ["2"]}
        )
        assert url.param_keys == frozenset({"foo", "Bar"})
        assert url.param_keys_lower == frozenset({"foo", "bar"})
    
    def test_base_url(self):
        url = ParsedURL(
            raw="https://example.com/path?query=1",
            scheme="https",
            host="example.com",
            path="/path",
            query="query=1"
        )
        assert url.base_url == "https://example.com/path"


class TestTarget:
    """Tests for Target dataclass."""
    
    def test_scope_normalized(self):
        target = Target(scope="  EXAMPLE.COM  ")
        assert target.scope == "example.com"
    
    def test_display_name_from_metadata(self):
        target = Target(scope="example.com", metadata={"name": "Example Site"})
        assert target.display_name == "Example Site"
    
    def test_display_name_fallback(self):
        target = Target(scope="example.com")
        assert target.display_name == "example.com"


class TestAnalysisResult:
    """Tests for AnalysisResult dataclass."""
    
    def test_match_count(self):
        result = AnalysisResult(
            analyzer_name="test",
            matched_urls={"url1", "url2", "url3"}
        )
        assert result.match_count == 3
    
    def test_match_rate(self):
        result = AnalysisResult(
            analyzer_name="test",
            matched_urls={"url1", "url2"},
            total_processed=10
        )
        assert result.match_rate == 20.0
    
    def test_match_rate_zero_total(self):
        result = AnalysisResult(analyzer_name="test")
        assert result.match_rate == 0.0
    
    def test_to_dict(self):
        result = AnalysisResult(
            analyzer_name="test",
            matched_urls={"url1"},
            total_processed=5
        )
        d = result.to_dict()
        assert d["analyzer_name"] == "test"
        assert d["match_count"] == 1
        assert d["total_processed"] == 5


class TestProbeResult:
    """Tests for ProbeResult dataclass."""
    
    def test_is_success(self):
        result = ProbeResult(url="https://example.com", host="example.com", alive=True, status_code=200)
        assert result.is_success is True
    
    def test_is_redirect(self):
        result = ProbeResult(url="https://example.com", host="example.com", alive=True, status_code=301)
        assert result.is_redirect is True
        assert result.is_success is False
    
    def test_is_client_error(self):
        result = ProbeResult(url="https://example.com", host="example.com", alive=True, status_code=404)
        assert result.is_client_error is True
    
    def test_is_server_error(self):
        result = ProbeResult(url="https://example.com", host="example.com", alive=True, status_code=500)
        assert result.is_server_error is True
