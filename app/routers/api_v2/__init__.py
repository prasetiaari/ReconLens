# app/routers/api_v2/__init__.py
"""
API v2 routes using new modular architecture.

These routes use the new services layer for clean separation of concerns.
Old routes remain functional for backwards compatibility.
"""

from fastapi import APIRouter

from app.routers.api_v2.targets import router as targets_router
from app.routers.api_v2.analyzers import router as analyzers_router

router = APIRouter(prefix="/api/v2", tags=["api-v2"])

router.include_router(targets_router)
router.include_router(analyzers_router)
