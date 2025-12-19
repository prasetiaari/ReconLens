# tests/conftest.py
"""
Pytest configuration and shared fixtures.
"""

import pytest
from pathlib import Path
import tempfile
import shutil


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    path = Path(tempfile.mkdtemp())
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def sample_urls():
    """Sample URLs for testing."""
    return [
        "https://example.com/login?next=https://evil.com",
        "https://example.com/admin/panel",
        "https://example.com/page?password=secret123",
        "https://example.com/api/users",
        "https://example.com/static/image.png",
        "https://example.com/robots.txt",
        "https://example.com/docs/report.pdf",
        "https://example.com/contact?email=test@gmail.com",
    ]


@pytest.fixture
def storage(temp_dir):
    """Create a FileStorage instance with temp directory."""
    from storage import FileStorage
    return FileStorage(base_dir=temp_dir)


@pytest.fixture
def target():
    """Create a sample Target."""
    from core.types import Target
    return Target(scope="example.com")
