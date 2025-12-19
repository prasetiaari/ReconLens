# tests/test_analyzers/test_open_redirect.py
"""
Tests for OpenRedirectAnalyzer.
"""

import pytest
from core.types import ParsedURL, Target
from analyzers.open_redirect import OpenRedirectAnalyzer


class TestOpenRedirectAnalyzer:
    """Tests for OpenRedirectAnalyzer."""
    
    @pytest.fixture
    def analyzer(self):
        return OpenRedirectAnalyzer()
    
    @pytest.fixture
    def target(self):
        return Target(scope="example.com")
    
    def test_name(self, analyzer):
        assert analyzer.name == "open_redirect"
    
    def test_description(self, analyzer):
        assert "redirect" in analyzer.description.lower()
    
    def test_detects_next_param(self, analyzer):
        parsed = ParsedURL(
            raw="https://example.com/login?next=https://evil.com",
            scheme="https",
            host="example.com",
            path="/login",
            params={"next": ["https://evil.com"]}
        )
        assert analyzer.should_include(parsed) is True
    
    def test_detects_redirect_param(self, analyzer):
        parsed = ParsedURL(
            raw="https://example.com/auth?redirect=http://bad.com",
            scheme="https",
            host="example.com",
            path="/auth",
            params={"redirect": ["http://bad.com"]}
        )
        assert analyzer.should_include(parsed) is True
    
    def test_detects_url_param(self, analyzer):
        parsed = ParsedURL(
            raw="https://example.com/go?url=http://bad.com",
            scheme="https",
            host="example.com",
            path="/go",
            params={"url": ["http://bad.com"]}
        )
        assert analyzer.should_include(parsed) is True
    
    def test_ignores_safe_params(self, analyzer):
        parsed = ParsedURL(
            raw="https://example.com/page?id=123",
            scheme="https",
            host="example.com",
            path="/page",
            params={"id": ["123"]}
        )
        assert analyzer.should_include(parsed) is False
    
    def test_case_insensitive(self, analyzer):
        parsed = ParsedURL(
            raw="https://example.com/login?NEXT=https://evil.com",
            scheme="https",
            host="example.com",
            path="/login",
            params={"NEXT": ["https://evil.com"]}
        )
        assert analyzer.should_include(parsed) is True
    
    def test_analyze_integration(self, analyzer, target):
        urls = [
            "https://example.com/login?next=https://evil.com",
            "https://example.com/page?id=123",
            "https://example.com/redirect?url=http://bad.com",
        ]
        result = analyzer.analyze(urls, target)
        
        assert result.analyzer_name == "open_redirect"
        assert result.match_count == 2
        assert result.total_processed == 3
    
    def test_scope_filtering(self, analyzer, target):
        urls = [
            "https://example.com/login?next=https://evil.com",
            "https://other.com/login?next=https://evil.com",  # Out of scope
        ]
        result = analyzer.analyze(urls, target)
        
        assert result.match_count == 1
    
    def test_metadata_extraction(self, analyzer):
        parsed = ParsedURL(
            raw="https://example.com/login?next=https://evil.com",
            scheme="https",
            host="example.com",
            path="/login",
            params={"next": ["https://evil.com"]}
        )
        meta = analyzer.extract_metadata(parsed)
        
        assert meta is not None
        assert "next" in meta["redirect_params"]
        assert meta["has_url_value"] is True
