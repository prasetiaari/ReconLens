# app/routers/graphs/api_subdomains.py
from fastapi import APIRouter
from pathlib import Path
from app.core.settings import get_settings
from app.core.templates import get_templates  # kalau perlu
from fastapi import Request
from fastapi.responses import JSONResponse
import json

router = APIRouter()

@router.get("/targets/{scope}/api/graphs/subdomains/ip-clusters.json")
def api_subdomains_ip_clusters(scope: str, request: Request):
    settings = get_settings(request)
    p = Path(settings.OUTPUTS_DIR) / scope / "__cache" / "rollup_group_by_ip.json"
    data = {}
    if p.exists():
        data = json.loads(p.read_text())
    return JSONResponse(data)
