# app/routers/graphs/page_ip_clusters.py
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from urllib.parse import urlencode

from app.core.templates import get_templates
from app.core.settings import get_settings

router = APIRouter()

@router.get("/targets/{scope}/graphs/subdomains/ip-clusters/page", response_class=HTMLResponse)
def subdomains_ip_clusters_page(scope: str, request: Request):
    templates = get_templates(request)
    settings = get_settings(request)

    # ambil param dari form (default sama dengan yang ada di template)
    q = request.query_params.get("q", "") or ""
    min_hosts = int(request.query_params.get("min_hosts") or 1)
    limit_ips = int(request.query_params.get("limit_ips") or 200)
    limit_hosts_per_ip = int(request.query_params.get("limit_hosts_per_ip") or 150)

    # build data_url untuk D3 (JSON API + query)
    qs = urlencode({
        "q": q,
        "min_hosts": min_hosts,
        "limit_ips": limit_ips,
        "limit_hosts_per_ip": limit_hosts_per_ip,
    })
    data_url = f"/targets/{scope}/api/graphs/subdomains/ip-clusters.json?{qs}"

    ctx = {
        "request": request,
        "scope": scope,
        "back_url": f"/targets/{scope}",
        "q": q,
        "min_hosts": min_hosts,
        "limit_ips": limit_ips,
        "limit_hosts_per_ip": limit_hosts_per_ip,
        "data_url": data_url,

        # opsional info di header kecil
        "nodes_count": None,
        "edges_count": None,
        "params_json": None,
    }
    return templates.TemplateResponse("subdomains_ip_clusters.html", ctx)
