from __future__ import annotations
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from app.deps import get_settings, get_templates
from app.services.targets import list_scopes

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    settings = get_settings(request)
    templates = get_templates(request)
    scopes = list_scopes(settings.OUTPUTS_DIR)
    return templates.TemplateResponse("home.html", {
        "request": request,
        "scopes": scopes,
    })
