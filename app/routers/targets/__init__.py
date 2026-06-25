from fastapi import APIRouter
from . import views, jobs, terminals, tags, viewer

router = APIRouter(prefix="/targets", tags=["Targets"])
router.include_router(terminals.router)
router.include_router(jobs.router)
router.include_router(tags.router)
router.include_router(viewer.router)
# views.router has catch-all /{scope}/{module} so it MUST be included last
router.include_router(views.router)