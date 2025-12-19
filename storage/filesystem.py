# storage/filesystem.py
"""
File-based storage implementation.

Uses the filesystem for data persistence with:
- Atomic writes to prevent corruption
- GZIP support for compression
- External sorting for large datasets
- JSON for structured data

This is the default storage backend.
"""

from __future__ import annotations

import json
import gzip
from pathlib import Path
from typing import Set, List, Dict, Any, Optional, Iterator, Union
from datetime import datetime

from storage.base import BaseStorage
from core.types import AnalysisResult, ProbeResult
from core.io_utils import (
    ensure_dir,
    read_nonempty_lines,
    write_lines_simple,
    write_text,
    is_gzip_path,
)
from core.exceptions import TargetNotFoundError, StorageError


class FileStorage(BaseStorage):
    """
    File-based storage implementation.
    
    Directory structure:
        base_dir/
        └── {scope}/
            ├── urls.txt
            ├── subdomains.txt
            ├── {analyzer_name}.txt
            ├── {analyzer_name}.meta.json
            ├── __cache/
            │   ├── probe_results.ndjson
            │   ├── url_enrich.json
            │   └── ...
            └── ...
    """
    
    CACHE_DIR = "__cache"
    
    def __init__(self, base_dir: Union[str, Path] = "outputs"):
        """
        Initialize file storage.
        
        Args:
            base_dir: Base directory for all scope data
        """
        self.base_dir = Path(base_dir)
        ensure_dir(self.base_dir)
    
    # ==================== Helpers ====================
    
    def _scope_path(self, scope: str) -> Path:
        """Get path to scope directory."""
        return self.base_dir / scope
    
    def _cache_path(self, scope: str) -> Path:
        """Get path to cache directory."""
        return self._scope_path(scope) / self.CACHE_DIR
    
    def _url_file_path(self, scope: str, name: str) -> Path:
        """Get path to URL file."""
        return self._scope_path(scope) / f"{name}.txt"
    
    def _meta_file_path(self, scope: str, name: str) -> Path:
        """Get path to metadata JSON file."""
        return self._scope_path(scope) / f"{name}.meta.json"
    
    def _json_file_path(self, scope: str, name: str) -> Path:
        """Get path to JSON file in cache."""
        return self._cache_path(scope) / f"{name}.json"
    
    # ==================== Scope Operations ====================
    
    def list_scopes(self) -> List[str]:
        """List all target scopes."""
        if not self.base_dir.exists():
            return []
        
        scopes = []
        for p in self.base_dir.iterdir():
            if p.is_dir() and not p.name.startswith("."):
                scopes.append(p.name)
        
        return sorted(scopes)
    
    def scope_exists(self, scope: str) -> bool:
        """Check if a scope exists."""
        return self._scope_path(scope).is_dir()
    
    def create_scope(self, scope: str) -> None:
        """Create a new scope directory."""
        path = self._scope_path(scope)
        ensure_dir(path)
        # Also create cache dir
        ensure_dir(self._cache_path(scope))
    
    def delete_scope(self, scope: str) -> None:
        """Delete a scope and all its data."""
        import shutil
        path = self._scope_path(scope)
        if path.exists():
            shutil.rmtree(path)
    
    # ==================== URL Operations ====================
    
    def save_urls(
        self,
        scope: str,
        name: str,
        urls: Set[str],
        append: bool = False,
    ) -> int:
        """Save URLs to file."""
        self.create_scope(scope)
        path = self._url_file_path(scope, name)
        
        if append and path.exists():
            existing = self.load_urls(scope, name)
            urls = existing | urls
        
        count_in, count_out = write_lines_simple(path, urls, dedup=True, sort_lines=True)
        return count_out
    
    def load_urls(self, scope: str, name: str) -> Set[str]:
        """Load all URLs into memory."""
        path = self._url_file_path(scope, name)
        if not path.exists():
            return set()
        
        return set(read_nonempty_lines(path))
    
    def iter_urls(self, scope: str, name: str) -> Iterator[str]:
        """Iterate URLs without loading all into memory."""
        path = self._url_file_path(scope, name)
        if path.exists():
            yield from read_nonempty_lines(path)
    
    def url_count(self, scope: str, name: str) -> int:
        """Get count of URLs without loading them."""
        path = self._url_file_path(scope, name)
        if not path.exists():
            return 0
        
        count = 0
        for _ in read_nonempty_lines(path):
            count += 1
        return count
    
    def urls_exist(self, scope: str, name: str) -> bool:
        """Check if URL data exists."""
        return self._url_file_path(scope, name).exists()
    
    # ==================== Analysis Operations ====================
    
    def save_analysis(self, scope: str, result: AnalysisResult) -> None:
        """Save analysis result (URLs + metadata)."""
        self.create_scope(scope)
        
        # Save URLs
        path = self._url_file_path(scope, result.analyzer_name)
        write_lines_simple(path, result.matched_urls, dedup=True, sort_lines=True)
        
        # Save metadata
        meta_path = self._meta_file_path(scope, result.analyzer_name)
        meta = result.to_dict()
        meta["saved_at"] = datetime.utcnow().isoformat() + "Z"
        write_text(meta_path, json.dumps(meta, indent=2, ensure_ascii=False))
    
    def load_analysis(
        self, scope: str, analyzer_name: str
    ) -> Optional[AnalysisResult]:
        """Load analysis result."""
        url_path = self._url_file_path(scope, analyzer_name)
        if not url_path.exists():
            return None
        
        urls = set(read_nonempty_lines(url_path))
        
        # Try to load metadata
        meta_path = self._meta_file_path(scope, analyzer_name)
        metadata = {}
        timestamp = None
        
        if meta_path.exists():
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                metadata = meta.get("metadata", {})
                timestamp = meta.get("timestamp")
            except Exception:
                pass
        
        return AnalysisResult(
            analyzer_name=analyzer_name,
            matched_urls=urls,
            total_processed=metadata.get("stats", {}).get("total", len(urls)),
            metadata=metadata,
            timestamp=timestamp,
        )
    
    def list_analyses(self, scope: str) -> List[str]:
        """List all analyzer names that have results."""
        scope_path = self._scope_path(scope)
        if not scope_path.exists():
            return []
        
        analyses = []
        for p in scope_path.glob("*.meta.json"):
            name = p.stem.replace(".meta", "")
            if self._url_file_path(scope, name).exists():
                analyses.append(name)
        
        return sorted(analyses)
    
    # ==================== Probe Operations ====================
    
    def save_probe_result(self, scope: str, result: ProbeResult) -> None:
        """Save a single probe result (append to NDJSON)."""
        self.create_scope(scope)
        path = self._cache_path(scope) / "probe_results.ndjson"
        
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(result.to_dict(), ensure_ascii=False))
            f.write("\n")
    
    def save_probe_results(
        self, scope: str, results: List[ProbeResult]
    ) -> int:
        """Save multiple probe results."""
        self.create_scope(scope)
        path = self._cache_path(scope) / "probe_results.ndjson"
        
        with open(path, "a", encoding="utf-8") as f:
            for result in results:
                f.write(json.dumps(result.to_dict(), ensure_ascii=False))
                f.write("\n")
        
        return len(results)
    
    def load_probe_results(self, scope: str) -> List[ProbeResult]:
        """Load all probe results."""
        return list(self.iter_probe_results(scope))
    
    def iter_probe_results(self, scope: str) -> Iterator[ProbeResult]:
        """Iterate probe results without loading all into memory."""
        path = self._cache_path(scope) / "probe_results.ndjson"
        if not path.exists():
            return
        
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    yield ProbeResult(
                        url=data["url"],
                        host=data["host"],
                        alive=data.get("alive", False),
                        status_code=data.get("status_code"),
                        content_type=data.get("content_type"),
                        size=data.get("size"),
                        title=data.get("title"),
                        ips=data.get("ips", []),
                        duration_ms=data.get("duration_ms", 0),
                        error=data.get("error"),
                        timestamp=data.get("timestamp"),
                    )
                except Exception:
                    continue
    
    # ==================== JSON Operations ====================
    
    def save_json(
        self, scope: str, name: str, data: Union[Dict, List]
    ) -> None:
        """Save JSON data to cache."""
        self.create_scope(scope)
        path = self._json_file_path(scope, name)
        ensure_dir(path)
        write_text(path, json.dumps(data, indent=2, ensure_ascii=False))
    
    def load_json(
        self, scope: str, name: str
    ) -> Optional[Union[Dict, List]]:
        """Load JSON data from cache."""
        path = self._json_file_path(scope, name)
        if not path.exists():
            return None
        
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    
    # ==================== Cache Operations ====================
    
    def get_cache_path(self, scope: str) -> Path:
        """Get cache directory path."""
        path = self._cache_path(scope)
        ensure_dir(path)
        return path
    
    def clear_cache(self, scope: str) -> None:
        """Clear cache for a scope."""
        import shutil
        path = self._cache_path(scope)
        if path.exists():
            shutil.rmtree(path)
            path.mkdir(parents=True, exist_ok=True)
    
    # ==================== Utility ====================
    
    def get_scope_path(self, scope: str) -> Path:
        """Get filesystem path for a scope."""
        return self._scope_path(scope)
    
    def __repr__(self) -> str:
        return f"<FileStorage(base_dir={self.base_dir!r})>"
