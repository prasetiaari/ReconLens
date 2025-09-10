# app/routers/subdomains_graph.py
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.core.templates import get_templates

router = APIRouter(prefix="/targets")


@router.get("/{scope}/subdomains/graph/clusters", response_class=HTMLResponse)
def graph_clusters_page(scope: str, request: Request):
    """
    Halaman graf IP–host dengan:
      - warna host berdasarkan HTTP class
      - klik host => lompat ke tabel Subdomains terfilter host
      - legenda warna
    """
    t = get_templates(request)
    return t.TemplateResponse("subdomains_ip_clusters.html", {
        "request": request,
        "scope": scope,
    })
