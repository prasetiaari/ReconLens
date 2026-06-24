from fastapi import APIRouter
from . import views, jobs, terminals, tags

router = APIRouter(prefix="/targets", tags=["Targets"])
router.include_router(terminals.router)
router.include_router(views.router)
router.include_router(jobs.router)
router.include_router(tags.router)