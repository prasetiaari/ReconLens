from __future__ import annotations
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from app.deps import get_settings, get_templates
from app.services.targets import load_summary, build_module_stats
from time import perf_counter
from app.services.targets import build_target_dashboard as build_dashboard_summary

router = APIRouter(prefix="/targets")

@router.get("/{scope}", response_class=HTMLResponse)
def target_detail(scope: str, request: Request):
    from time import perf_counter
    t0 = perf_counter()
    settings = get_settings(request)
    templates = get_templates(request)

    t1 = perf_counter()
    summary = load_summary(settings.OUTPUTS_DIR, scope)
    t2 = perf_counter()
    stats = build_module_stats(settings.OUTPUTS_DIR, scope, settings.MODULES)
    t3 = perf_counter()
    dash = build_dashboard_summary(settings.OUTPUTS_DIR, scope)
   
    env = templates.env
    has_timeago = "timeago" in env.filters
    has_humansize = "humansize" in env.filters

    resp = templates.TemplateResponse("target_detail.html", {
        "request": request,
        "scope": scope,
        "summary": summary,
        "stats": stats,
        "dash": dash,
        "has_timeago": has_timeago,
        "has_humansize": has_humansize,
    })
    t4 = perf_counter()

    print(
        f"[perf] /targets/{scope} total={(t4-t0)*1000:.1f}ms "
        f"settings={(t1-t0)*1000:.1f}ms summary={(t2-t1)*1000:.1f}ms "
        f"build_stats={(t3-t2)*1000:.1f}ms render={(t4-t3)*1000:.1f}ms",
        flush=True,  # << penting
    )
    return resp
