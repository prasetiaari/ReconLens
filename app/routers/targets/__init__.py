from fastapi import APIRouter
from . import views, jobs

router = APIRouter(prefix="/targets", tags=["Targets"])
router.include_router(views.router)
router.include_router(jobs.router)