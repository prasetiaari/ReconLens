from __future__ import annotations
from fastapi import APIRouter, Request, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from app.deps import get_settings, get_templates
from app.services.modules import module_page, module_file, module_count
from math import ceil

router = APIRouter(prefix="/targets")

'''@router.get("/{scope}/{module}", response_class=HTMLResponse)
def viewer(scope: str, module: str, request: Request,
           page: int = Query(1, ge=1), page_size: int = Query(None),
           q: str | None = Query(None)):
    settings = get_settings(request)
    templates = get_templates(request)
    page_size = page_size or settings.PAGE_SIZE_DEFAULT
    page_size = min(page_size, settings.PAGE_SIZE_MAX)
    # initial render; tbody akan di-load via HTMX
    total = module_count(settings.OUTPUTS_DIR, scope, settings.MODULES, module)
    return templates.TemplateResponse("viewer.html", {
        "request": request,
        "scope": scope,
        "module": module,
        "q": q or "",
        "page": page,
        "page_size": page_size,
        "total": total
    })

@router.get("/{scope}/{module}/rows", response_class=HTMLResponse)
def viewer_rows(scope: str, module: str, request: Request,
                page: int = Query(1, ge=1), page_size: int = Query(None),
                q: str | None = Query(None)):
    settings = get_settings(request)
    templates = get_templates(request)
    page_size = page_size or settings.PAGE_SIZE_DEFAULT
    page_size = min(page_size, settings.PAGE_SIZE_MAX)

    items, total = module_page(
        settings.OUTPUTS_DIR, scope, settings.MODULES, module,
        page, page_size, q
    )
    total_pages = max(1, ceil(total / page_size))
    page = max(1, min(page, total_pages))
    has_prev = page > 1
    has_next = page < total_pages

    # buat window halaman (mis. 1..5, 6..10, dsb)
    WINDOW = 7
    half = WINDOW // 2
    start = max(1, page - half)
    end = min(total_pages, start + WINDOW - 1)
    # geser start kalau jendela belum penuh
    start = max(1, min(start, end - WINDOW + 1))

    pages = list(range(start, end + 1))

    return templates.TemplateResponse("_table_rows.html", {
        "request": request,
        "rows": items,
        "page": page,
        "page_size": page_size,
        "total": total,
        "has_prev": has_prev,
        "has_next": has_next,
        "total_pages": total_pages,
        "pages": pages,
        "q": q or "",
        # untuk link
        "scope": scope,
        "module": module,
    })
'''
@router.get("/{scope}/download/{filename}", response_class=PlainTextResponse)
def download(scope: str, filename: str, request: Request):
    settings = get_settings(request)
    fp = (settings.OUTPUTS_DIR / scope / filename).resolve()
    if settings.OUTPUTS_DIR.resolve() not in fp.parents:
        return PlainTextResponse("Invalid path", status_code=400)
    if not fp.exists():
        return PlainTextResponse("Not found", status_code=404)
    text = fp.read_text(encoding="utf-8", errors="ignore")
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return PlainTextResponse(text, headers=headers)
