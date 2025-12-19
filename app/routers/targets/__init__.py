from fastapi import APIRouter
from . import views, jobs, host_views

router = APIRouter(prefix="/targets", tags=["Targets"])
router.include_router(views.router)
router.include_router(jobs.router)
router.include_router(host_views.router)