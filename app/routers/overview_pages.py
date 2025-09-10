# app/routers/overview_pages.py
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.core.settings import get_settings
from app.deps import get_templates

router = APIRouter()

@router.get("/targets/{scope}/overview", response_class=HTMLResponse)
def overview_page(scope: str, request: Request):
    settings = get_settings(request)
    templates = get_templates(request)

    # API endpoints yang dipakai halaman ini
    api_status = f"/targets/{scope}/api/overview/status-codes.json"  # kamu sudah punya router-nya
    api_ctypes = f"/targets/{scope}/api/overview/content-types.json"

    return templates.TemplateResponse(
        "overview.html",
        {
            "request": request,
            "scope": scope,
            "api_status": api_status,
            "api_ctypes": api_ctypes,
        },
    )

@router.get("/targets/{scope}/overview", response_class=HTMLResponse)
def overview_page(scope: str, request: Request):
    settings = get_settings(request)
    templates = get_templates(request)

    return templates.TemplateResponse("overview.html", {
        "request": request,
        "scope": scope,
        "available_modules": list(settings.MODULES.keys()),  # << tambah ini
    })
