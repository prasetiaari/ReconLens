# tests/test_services/test_analysis.py
"""
Tests for AnalysisService.
"""

import pytest
from services import AnalysisService, TargetService
from storage import FileStorage
from core.exceptions import TargetNotFoundError, AnalyzerNotFoundError


class TestAnalysisService:
    """Tests for AnalysisService."""
    
    @pytest.fixture
    def service(self, storage):
        return AnalysisService(storage=storage)
    
    @pytest.fixture
    def target_service(self, storage):
        return TargetService(storage=storage)
    
    def test_get_available_analyzers(self, service):
        analyzers = service.get_available_analyzers()
        assert len(analyzers) >= 7
        assert any(a["name"] == "open_redirect" for a in analyzers)
    
    def test_run_analyzer(self, service, storage):
        # Setup
        storage.create_scope("test.com")
        storage.save_urls("test.com", "urls", {
            "https://test.com/login?next=https://evil.com",
            "https://test.com/page?id=123",
        })
        
        # Run
        result = service.run_analyzer("test.com", "open_redirect")
        
        # Verify
        assert result.analyzer_name == "open_redirect"
        assert result.match_count == 1
        assert result.total_processed == 2
    
    def test_run_analyzer_target_not_found(self, service):
        with pytest.raises(TargetNotFoundError):
            service.run_analyzer("nonexistent.com", "open_redirect")
    
    def test_run_analyzer_not_found(self, service, storage):
        storage.create_scope("test.com")
        
        with pytest.raises(AnalyzerNotFoundError):
            service.run_analyzer("test.com", "nonexistent_analyzer")
    
    def test_run_all_analyzers(self, service, storage):
        # Setup
        storage.create_scope("test.com")
        storage.save_urls("test.com", "urls", {
            "https://test.com/login?next=https://evil.com",
            "https://test.com/admin/panel",
        })
        
        # Run all
        results = service.run_all_analyzers("test.com")
        
        # Verify
        assert len(results) >= 7
        
        # Find specific results
        open_redirect = next(r for r in results if r.analyzer_name == "open_redirect")
        sensitive_paths = next(r for r in results if r.analyzer_name == "sensitive_paths")
        
        assert open_redirect.match_count == 1
        assert sensitive_paths.match_count == 2  # /login and /admin/panel
    
    def test_list_analyses(self, service, storage):
        # Setup
        storage.create_scope("test.com")
        storage.save_urls("test.com", "urls", {"https://test.com/login?next=x"})
        
        # Run
        service.run_analyzer("test.com", "open_redirect")
        
        # List
        analyses = service.list_analyses("test.com")
        
        assert any(a["analyzer_name"] == "open_redirect" for a in analyses)
    
    def test_get_analysis_result(self, service, storage):
        # Setup
        storage.create_scope("test.com")
        storage.save_urls("test.com", "urls", {"https://test.com/login?next=x"})
        service.run_analyzer("test.com", "open_redirect")
        
        # Get
        result = service.get_analysis_result("test.com", "open_redirect")
        
        assert result is not None
        assert result.analyzer_name == "open_redirect"
    
    def test_delete_analysis(self, service, storage):
        # Setup
        storage.create_scope("test.com")
        storage.save_urls("test.com", "urls", {"https://test.com/login?next=x"})
        service.run_analyzer("test.com", "open_redirect")
        
        # Delete
        service.delete_analysis("test.com", "open_redirect")
        
        # Verify deleted
        result = service.get_analysis_result("test.com", "open_redirect")
        assert result is None
