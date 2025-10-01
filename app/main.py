from __future__ import annotations
from datetime import datetime, timezone
from time import perf_counter

from fastapi import FastAPI, Request, APIRouter
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates      # ⬅ konsisten
from fastapi.responses import RedirectResponse
from dateutil import parser as dtparser

from app.config import Settings

# Routers
from app.routers import settings as settings_router
from app.routers import ai as ai_router
from app.routers import ai_commands as ai_commands_router  # NEW
from app.routers import ai_cmd as ai_cmd_router

from app.routers import graphs as graphs_router
from app.routers.graphs.pages_index import router as graphs_pages_index_router

from app.routers import home as home_router
from app.routers import targets_api as targets_api_router
from app.routers import targets as targets_router
#from app.routers import sensitive_paths as sensitive_paths_router
from app.routers import subdomains as subdomains_router
from app.routers import graphs_subdomains as graphs_subdomains_router

from app.routers.graphs.page_ip_clusters import router as graphs_pages_ip_clusters_router
from app.routers.graphs.api_subdomains import router as graphs_api_subdomains_router
from app.routers.graphs import api_router as graphs_api_router, pages_router as graphs_pages_router
from app.routers.overview_api import router as overview_api_router
from app.routers.overview_pages import router as overview_pages_router
from app.routers.overview_status_codes import router as overview_status_codes_router

# NEW generic viewer
from app.routers import pages as pages_router
from app.routers import viewer as viewer_router

def create_app() -> FastAPI:
    settings = Settings()
    app = FastAPI(title="Pentest URLs Viewer", version="0.1.0")

    # Templates (Jinja)
    templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))
    from jinja2.bccache import FileSystemBytecodeCache
    import os
    cache_dir = os.path.join(os.getcwd(), ".jinja_cache")
    os.makedirs(cache_dir, exist_ok=True)
    templates.env.bytecode_cache = FileSystemBytecodeCache(directory=cache_dir)
    templates.env.filters["humansize"] = humansize
    templates.env.filters["timeago"] = timeago

    app.state.templates = templates
    app.state.settings = settings

    # Static
    app.mount("/static", StaticFiles(directory=str(settings.STATIC_DIR)), name="static")

    # Routers (tanpa duplikat)    
    app.include_router(settings_router.router)
    app.include_router(ai_router.router)               # yang lama (insights, dll.)
    app.include_router(ai_commands_router.router)      # yang baru: AI Command
    app.include_router(ai_cmd_router.router)
    app.include_router(graphs_pages_index_router)
    
    app.include_router(home_router.router)
    app.include_router(targets_router.router)
    app.include_router(subdomains_router.router)
    #app.include_router(sensitive_paths_router.router)

    # Generic module viewer (OPEN_REDIRECT dkk)
    app.include_router(viewer_router.router)

    # Overview & Graphs
    app.include_router(overview_api_router)
    app.include_router(overview_pages_router)
    app.include_router(overview_status_codes_router)

    app.include_router(graphs_subdomains_router.router)
    
    app.include_router(graphs_pages_ip_clusters_router)
    app.include_router(graphs_api_subdomains_router)
    app.include_router(graphs_api_router)
    app.include_router(graphs_pages_router)
    app.include_router(targets_api_router.router)
    app.include_router(pages_router.router)
    
    # Alias: /targets/{scope}/open_redirect -> /targets/{scope}/module/open_redirect
    alias_router = APIRouter()
    @alias_router.get("/targets/{scope}/open_redirect")
    def open_redirect_alias(scope: str):
        return RedirectResponse(url=f"/targets/{scope}/module/open_redirect")
    app.include_router(alias_router)   # ⬅ PENTING: include alias

    @alias_router.get("/targets/{scope}/documents")
    def documents_alias(scope: str):
        return RedirectResponse(url=f"/targets/{scope}/module/documents")
    app.include_router(alias_router)   # ⬅ PENTING: include alias
    # in-memory caches
    app.state.probe_cache = {}
    return app

def humansize(n):
    if n is None:
        return "-"
    try:
        n = float(n)
    except Exception:
        return "-"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.0f} {units[i]}" if i == 0 else f"{n:.1f} {units[i]}"

def timeago(iso_str: str):
    try:
        t = dtparser.isoparse(iso_str)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        sec = int((now - t).total_seconds())
        if sec < 60: return f"{sec}s ago"
        mins = sec // 60
        if mins < 60: return f"{mins}m ago"
        hrs = mins // 60
        if hrs < 24: return f"{hrs}h ago"
        days = hrs // 24
        return f"{days}d ago"
    except Exception:
        return iso_str

app = create_app()

# Debug daftar route
for r in app.router.routes:
    try:
        mod = getattr(r, "endpoint", None)
        mod = getattr(mod, "__module__", "?")
        fn  = getattr(r, "name", "?")
        #print("ROUTE:", r.methods, r.path, "->", mod, "/", fn)
    except Exception:
        pass

@app.middleware("http")
async def timing_mw(request: Request, call_next):
    t0 = perf_counter()
    response = await call_next(request)
    t1 = perf_counter()
    path = request.url.path
    if not path.startswith("/static"):
        print(f"[perf] {request.method} {path} total={(t1-t0)*1000:.1f}ms", flush=True)
    return response
