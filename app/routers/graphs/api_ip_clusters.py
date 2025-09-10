from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from app.deps import get_settings
from app.graphs.ip_clusters import build_ip_clusters_graph

router = APIRouter()

@router.get("/subdomains/ip-clusters.json", response_class=JSONResponse)
def api_ip_clusters(scope: str, request: Request):
    settings = get_settings(request)
    qp = request.query_params
    payload = build_ip_clusters_graph(
        outputs_dir=settings.OUTPUTS_DIR,
        scope=scope,
        q=qp.get("q") or "",
        min_hosts=int(qp.get("min_hosts") or 1),
        limit_ips=int(qp.get("limit_ips") or 200),
        limit_hosts_per_ip=int(qp.get("limit_hosts_per_ip") or 150),
    )
    return JSONResponse(payload)
