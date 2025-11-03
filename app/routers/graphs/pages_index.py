from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from app.core.templates import get_templates

router = APIRouter()

@router.get("/targets/{scope}/graphs", response_class=HTMLResponse)
def graphs_index(scope: str, request: Request):
    templates = get_templates(request)
    return templates.TemplateResponse("graphs/index.html", {
        "request": request,
        "scope": scope,
    })
