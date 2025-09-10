# app/routers/graphs/__init__.py
from fastapi import APIRouter

from .pages_index import router as pages_index_router
from .page_ip_clusters import router as page_ip_clusters_router
from .page_status_codes import router as page_status_codes_router   # <-- tambah ini
#from .overview_status_codes import router as overview_status_codes_router

from .api_subdomains import router as api_subdomains_router
from .api_status_codes import router as api_status_codes_router     # <-- pastikan sudah ada

# API routers
api_router = APIRouter()
api_router.include_router(api_subdomains_router)
api_router.include_router(api_status_codes_router)                  # <-- pastikan include

# Pages routers
pages_router = APIRouter()
pages_router.include_router(pages_index_router)
pages_router.include_router(page_ip_clusters_router)
pages_router.include_router(page_status_codes_router)               # <-- include halaman baru

# agar from app.routers.graphs import api_router, pages_router bekerja
