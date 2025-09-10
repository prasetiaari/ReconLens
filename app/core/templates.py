# app/core/templates.py
# pastikan bentuknya SESINGKAT ini
from starlette.templating import Jinja2Templates
from fastapi import Request

def get_templates(request: Request) -> Jinja2Templates:
    # JANGAN membuat Jinja2Templates baru di sini.
    # Selalu pakai yang sudah disiapkan di app.state.templates (startup).
    return request.app.state.templates
