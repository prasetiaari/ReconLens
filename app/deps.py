from __future__ import annotations
from fastapi import Request
from app.config import Settings
from typing import Any, Dict, Optional, Union

def get_settings(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore

def get_templates(request: Request):
    return request.app.state.templates  # type: ignore

def as_cfg(settings: Optional[Union[Dict[str, Any], Any]]) -> Dict[str, Any]:
    """
    Minimal normalizer: accept dict or Pydantic Settings (v1/v2) and
    return plain dict. Safe to call with None.
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