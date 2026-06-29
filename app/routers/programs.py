from fastapi import APIRouter, Request, Form
from fastapi.responses import JSONResponse

from app.deps import get_settings
from app.services.program_meta import update_program_meta

router = APIRouter(prefix="/api/programs", tags=["programs"])

@router.post("/{program_name}/meta")
def update_meta(
    program_name: str,
    platform: str = Form(None),
    url: str = Form(None),
    notes: str = Form(None),
    request: Request = None
):
    settings = get_settings(request)
    
    meta = {}
    if platform is not None:
        meta["platform"] = platform.strip()
    if url is not None:
        meta["url"] = url.strip()
    if notes is not None:
        meta["notes"] = notes.strip()
        
    update_program_meta(settings.OUTPUTS_DIR, program_name, meta)
    
    # Reload page to reflect changes
    resp = JSONResponse({"ok": True})
    resp.headers["HX-Refresh"] = "true"
    return resp
