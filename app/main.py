from __future__ import annotations
from time import perf_counter
from fastapi import FastAPI, Request, APIRouter
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from datetime import datetime, timezone
from dateutil import parser as dtparser
import os

from app.config import Settings
from app.core.routers import load_all_routers
from app.core.utils.filters import humansize, timeago

# --- Templates Initialization ---
def init_templates(settings: Settings) -> Jinja2Templates:
    templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))
    cache_dir = os.path.join(os.getcwd(), ".jinja_cache")
    os.makedirs(cache_dir, exist_ok=True)

    from jinja2.bccache import FileSystemBytecodeCache
    templates.env.bytecode_cache = FileSystemBytecodeCache(directory=cache_dir)
    templates.env.filters["humansize"] = humansize
    templates.env.filters["timeago"] = timeago
    return templates


# --- Alias routes ---
def add_alias_routes(app: FastAPI):
    alias_router = APIRouter()

    @alias_router.get("/targets/{scope}/open_redirect")
    async def open_redirect_alias(scope: str):
        return RedirectResponse(url=f"/targets/{scope}/module/open_redirect")

    @alias_router.get("/targets/{scope}/documents")
    async def documents_alias(scope: str):
        return RedirectResponse(url=f"/targets/{scope}/module/documents")

    app.include_router(alias_router)


# --- Middleware: performance timing ---
async def timing_middleware(request: Request, call_next):
    t0 = perf_counter()
    response = await call_next(request)
    t1 = perf_counter()
    path = request.url.path
    if not path.startswith("/static"):
        print(f"[perf] {request.method} {path} total={(t1-t0)*1000:.1f}ms", flush=True)
    return response


# --- Factory ---
def create_app() -> FastAPI:
    settings = Settings()
    app = FastAPI(title="Pentest URLs Viewer", version="0.2.0")

    # Attach state
    app.state.settings = settings
    app.state.templates = init_templates(settings)
    app.state.probe_cache = {}

    # Static files
    app.mount("/static", StaticFiles(directory=str(settings.STATIC_DIR)), name="static")

    # Include all routers (auto loader)
    load_all_routers(app)

    # Aliases
    add_alias_routes(app)

    # Middleware
    app.middleware("http")(timing_middleware)

    return app


app = create_app()