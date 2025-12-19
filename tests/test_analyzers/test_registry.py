# tests/test_analyzers/test_registry.py
"""
Tests for analyzer registry.
"""

import pytest
from analyzers import (
    get_analyzer,
    list_analyzers,
    get_all_analyzers,
    analyzer_exists,
    get_analyzer_info,
)
from analyzers.base import BaseAnalyzer
from core.exceptions import AnalyzerNotFoundError


class TestAnalyzerRegistry:
    """Tests for analyzer registry functions."""
    
    def test_list_analyzers(self):
        names = list_analyzers()
        assert isinstance(names, list)
        assert len(names) >= 7  # We created 7 analyzers
        assert "open_redirect" in names
        assert "sensitive_paths" in names
    
    def test_get_analyzer(self):
        analyzer = get_analyzer("open_redirect")
        assert isinstance(analyzer, BaseAnalyzer)
        assert analyzer.name == "open_redirect"
    
    def test_get_analyzer_not_found(self):
        with pytest.raises(AnalyzerNotFoundError) as exc:
            get_analyzer("nonexistent_analyzer")
        
        assert exc.value.name == "nonexistent_analyzer"
        assert "available" in exc.value.context
    
    def test_get_all_analyzers(self):
        analyzers = get_all_analyzers()
        assert isinstance(analyzers, list)
        assert all(isinstance(a, BaseAnalyzer) for a in analyzers)
        assert len(analyzers) >= 7
    
    def test_analyzer_exists(self):
        assert analyzer_exists("open_redirect") is True
        assert analyzer_exists("nonexistent") is False
    
    def test_get_analyzer_info(self):
        info = get_analyzer_info()
        assert isinstance(info, list)
        
        names = [i["name"] for i in info]
        assert "open_redirect" in names
        
        # Check structure
        for item in info:
            assert "name" in item
            assert "description" in item
            assert "output_filename" in item
