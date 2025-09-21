from __future__ import annotations
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

# Jika proyekmu sudah punya get_settings/get_templates via deps.py:
from ..deps import get_templates  # pastikan impor ini sesuai strukturmu

router = APIRouter()

@router.get("/about", response_class=HTMLResponse)
async def about_page(request: Request):
    T = get_templates(request)
    return T.TemplateResponse("about.html", {"request": request})
