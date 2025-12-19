# tests/test_storage/test_filesystem.py
"""
Tests for FileStorage implementation.
"""

import pytest
from pathlib import Path
from storage import FileStorage
from core.types import AnalysisResult, ProbeResult


class TestFileStorage:
    """Tests for FileStorage."""
    
    def test_create_scope(self, storage):
        storage.create_scope("test.com")
        assert storage.scope_exists("test.com")
    
    def test_list_scopes(self, storage):
        storage.create_scope("a.com")
        storage.create_scope("b.com")
        scopes = storage.list_scopes()
        assert "a.com" in scopes
        assert "b.com" in scopes
    
    def test_delete_scope(self, storage):
        storage.create_scope("delete-me.com")
        assert storage.scope_exists("delete-me.com")
        
        storage.delete_scope("delete-me.com")
        assert not storage.scope_exists("delete-me.com")
    
    def test_save_and_load_urls(self, storage):
        storage.create_scope("test.com")
        urls = {"https://test.com/page1", "https://test.com/page2"}
        
        count = storage.save_urls("test.com", "urls", urls)
        assert count == 2
        
        loaded = storage.load_urls("test.com", "urls")
        assert loaded == urls
    
    def test_save_urls_append(self, storage):
        storage.create_scope("test.com")
        storage.save_urls("test.com", "urls", {"url1"})
        storage.save_urls("test.com", "urls", {"url2"}, append=True)
        
        loaded = storage.load_urls("test.com", "urls")
        assert loaded == {"url1", "url2"}
    
    def test_iter_urls(self, storage):
        storage.create_scope("test.com")
        urls = {"url1", "url2", "url3"}
        storage.save_urls("test.com", "urls", urls)
        
        iterated = set(storage.iter_urls("test.com", "urls"))
        assert iterated == urls
    
    def test_url_count(self, storage):
        storage.create_scope("test.com")
        storage.save_urls("test.com", "urls", {"url1", "url2", "url3"})
        
        assert storage.url_count("test.com", "urls") == 3
    
    def test_urls_exist(self, storage):
        storage.create_scope("test.com")
        assert not storage.urls_exist("test.com", "urls")
        
        storage.save_urls("test.com", "urls", {"url1"})
        assert storage.urls_exist("test.com", "urls")
    
    def test_save_and_load_analysis(self, storage):
        storage.create_scope("test.com")
        
        result = AnalysisResult(
            analyzer_name="open_redirect",
            matched_urls={"url1", "url2"},
            total_processed=10,
        )
        
        storage.save_analysis("test.com", result)
        
        loaded = storage.load_analysis("test.com", "open_redirect")
        assert loaded is not None
        assert loaded.analyzer_name == "open_redirect"
        assert loaded.matched_urls == {"url1", "url2"}
    
    def test_list_analyses(self, storage):
        storage.create_scope("test.com")
        
        storage.save_analysis("test.com", AnalysisResult(
            analyzer_name="analyzer1",
            matched_urls={"url1"},
        ))
        storage.save_analysis("test.com", AnalysisResult(
            analyzer_name="analyzer2",
            matched_urls={"url2"},
        ))
        
        analyses = storage.list_analyses("test.com")
        assert "analyzer1" in analyses
        assert "analyzer2" in analyses
    
    def test_save_and_load_json(self, storage):
        storage.create_scope("test.com")
        
        data = {"key": "value", "number": 42}
        storage.save_json("test.com", "config", data)
        
        loaded = storage.load_json("test.com", "config")
        assert loaded == data
    
    def test_probe_results(self, storage):
        storage.create_scope("test.com")
        
        probe = ProbeResult(
            url="https://test.com",
            host="test.com",
            alive=True,
            status_code=200,
        )
        
        storage.save_probe_result("test.com", probe)
        
        loaded = storage.load_probe_results("test.com")
        assert len(loaded) == 1
        assert loaded[0].url == "https://test.com"
        assert loaded[0].status_code == 200
    
    def test_clear_cache(self, storage):
        storage.create_scope("test.com")
        storage.save_json("test.com", "cached_data", {"key": "value"})
        
        storage.clear_cache("test.com")
        
        assert storage.load_json("test.com", "cached_data") is None
