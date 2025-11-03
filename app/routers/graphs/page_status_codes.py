# app/routers/graphs/page_status_codes.py
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from app.core.templates import get_templates

router = APIRouter()

@router.get("/targets/{scope}/graphs/status-codes", response_class=HTMLResponse)
def status_codes_page(scope: str, request: Request):
    templates = get_templates(request)

    # echo query params agar form prefilled & dipakai JS saat fetch
    qp = request.query_params
    modules = qp.get("modules", "")
    host_contains = qp.get("host_contains", "")
    host_exact = qp.get("host_exact", "")

    api_url = f"/targets/{scope}/api/graphs/status-codes.json"
    # biarkan JS yang compose query string dari form, tapi kita kasih initial params juga
    ctx = {
        "request": request,
        "scope": scope,
        "api_url": api_url,
        "modules": modules,
        "host_contains": host_contains,
        "host_exact": host_exact,
    }
    return templates.TemplateResponse("graphs/status_codes.html", ctx)
