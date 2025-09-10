from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from app.core.settings import get_settings
from app.graphs.sensitive_paths import build_sensitive_paths_graph

router = APIRouter()

@router.get("/sensitive-paths.json", response_class=JSONResponse)
def sensitive_paths_json(scope: str, request: Request):
    settings = get_settings(request)
    payload = build_sensitive_paths_graph(settings.OUTPUTS_DIR, scope, request.query_params)
    return JSONResponse(payload)
