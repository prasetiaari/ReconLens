# storage/__init__.py
"""
Storage abstraction layer.

Provides interface for data persistence, decoupling business logic
from specific storage implementations.

Current implementations:
- FileStorage: File-based storage (default)

Future implementations:
- SQLiteStorage: SQLite database
- PostgresStorage: PostgreSQL database

Usage:
    from storage import FileStorage
    
    storage = FileStorage(base_dir="outputs")
    storage.save_urls("example.com", "urls", urls)
    urls = storage.load_urls("example.com", "urls")
"""

from storage.base import BaseStorage
from storage.filesystem import FileStorage

__all__ = [
    "BaseStorage",
    "FileStorage",
]
