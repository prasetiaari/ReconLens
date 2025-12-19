# app/deps.py
"""
FastAPI dependencies for dependency injection.

Provides access to:
- Settings
- Templates
- Storage (new)
- Services (new)
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from fastapi import Request, Depends
from typing import Any, Dict, Optional, Union

from app.config import Settings


# ==================== Existing Dependencies ====================

def get_settings(request: Request) -> Settings:
    """Get settings from app state."""
    return request.app.state.settings  # type: ignore


def get_templates(request: Request):
    """Get Jinja2 templates from app state."""
    return request.app.state.templates  # type: ignore


def as_cfg(settings: Optional[Union[Dict[str, Any], Any]]) -> Dict[str, Any]:
    """
    Normalize settings to dict.
    Accept dict or Pydantic Settings (v1/v2).
    """
    if settings is None:
        return {}
    if isinstance(settings, dict):
        return settings
    # pydantic v2
    if hasattr(settings, "model_dump") and callable(getattr(settings, "model_dump")):
        return settings.model_dump()
    # pydantic v1
    if hasattr(settings, "dict") and callable(getattr(settings, "dict")):
        return settings.dict()
    return {}


# ==================== New Dependencies (Services) ====================

@lru_cache
def get_storage():
    """
    Get storage instance (singleton).
    
    Returns:
        FileStorage instance
    """
    from storage import FileStorage
    from app.config import Settings
    
    settings = Settings()
    return FileStorage(base_dir=settings.OUTPUTS_DIR)


def get_storage_from_request(request: Request):
    """
    Get storage from request (for dependency injection in routes).
    
    Usage:
        @router.get("/")
        def endpoint(storage = Depends(get_storage_from_request)):
            ...
    """
    return get_storage()


@lru_cache
def get_target_service():
    """
    Get target service instance (singleton).
    
    Returns:
        TargetService instance
    """
    from services import TargetService
    return TargetService(storage=get_storage())


def get_target_service_from_request(request: Request):
    """Get target service for route injection."""
    return get_target_service()


@lru_cache
def get_analysis_service():
    """
    Get analysis service instance (singleton).
    
    Returns:
        AnalysisService instance
    """
    from services import AnalysisService
    return AnalysisService(storage=get_storage())


def get_analysis_service_from_request(request: Request):
    """Get analysis service for route injection."""
    return get_analysis_service()


# ==================== Convenience Dependencies ====================

def get_all_services(request: Request) -> Dict[str, Any]:
    """
    Get all services bundled together.
    
    Usage:
        @router.get("/")
        def endpoint(services = Depends(get_all_services)):
            services["target"].list_targets()
            services["analysis"].run_analyzer(...)
    """
    return {
        "storage": get_storage(),
        "target": get_target_service(),
        "analysis": get_analysis_service(),
    }