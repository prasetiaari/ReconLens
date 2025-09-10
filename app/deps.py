from __future__ import annotations
from fastapi import Request
from app.config import Settings

def get_settings(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore

def get_templates(request: Request):
    return request.app.state.templates  # type: ignore
