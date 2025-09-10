# app/routers/subdomains_api.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, Iterable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.settings import get_settings

router = APIRouter(prefix="/api/subdomains")


def _outputs_dir(request: Request) -> Path:
    return Path(get_settings(request).OUTPUTS_DIR)


def _load_json(p: Path) -> Any:
    try:
        if p.exists():
            return json.loads(p.read_text("utf-8"))
    except Exception:
        pass
    return None


def _iter_ndjson(p: Path) -> Iterable[dict]:
    if not p.exists():
        return
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def _class_from_code(code: int | None) -> str:
    if code is None:
        return "none"
    c = int(code) // 100
    return f"{c}xx"


@router.get("/{scope}/clusters")
def clusters(scope: str, request: Request,
             q: str = "",
             limit_ips: int = 200,
             limit_hosts_per_ip: int = 150,
             min_hosts: int = 1):
    """
    Kembalikan graph nodes/edges untuk IP–host.
    Sekarang setiap node 'host' diperkaya field:
      - alive (bool)
      - code (int|None)
      - http_class ('2xx'|'3xx'|'4xx'|'5xx'|'none')
      - title, size, last_probe (jika ada)
    """
    outdir = _outputs_dir(request) / scope / "__cache"

    # sumber utama edges host<->ip
    edges_path = outdir / "host_ip_edges.ndjson"

    # optional: enrich status host (hasil probe subdomains)
    enrich_path = outdir / "subdomains_enrich.json"
    enrich_map: Dict[str, dict] = _load_json(enrich_path) or {}

    # kumpulkan edges terfilter
    edges = []
    seen_hosts: set[str] = set()
    seen_ips: set[str] = set()

    for rec in _iter_ndjson(edges_path):
        host = rec.get("host") or ""
        ip = rec.get("ip") or ""
        if not host or not ip:
            continue
        if q and q.lower() not in host.lower():
            continue

        edges.append({"source": ip, "target": host})
        seen_hosts.add(host)
        seen_ips.add(ip)

        if len(seen_ips) >= limit_ips:
            # batasi jumlah IP (host tetap ikut sesuai edges yang sudah terkumpul)
            break

    # siapkan nodes
    nodes: list[dict] = []

    # IP nodes
    for ip in sorted(seen_ips):
        # hitung degree host / ip
        deg = sum(1 for e in edges if e["source"] == ip)
        if deg < min_hosts:
            # filter IP dengan host sedikit
            continue
        nodes.append({
            "id": ip,
            "label": ip,
            "type": "ip",
            "degree": deg,
        })
    kept_ips = {n["id"] for n in nodes}

    # Host nodes (dengan enrich bila ada)
    for host in sorted(seen_hosts):
        # host harus terhubung ke salah satu kept_ips
        if not any(e["target"] == host and e["source"] in kept_ips for e in edges):
            continue

        e = enrich_map.get(host) or {}
        code = e.get("code")
        http_class = _class_from_code(code if isinstance(code, int) else None)
        nodes.append({
            "id": host,
            "label": host,
            "type": "host",
            "alive": bool(e.get("alive")) if e else False,
            "code": code if isinstance(code, int) else None,
            "http_class": http_class,
            "title": e.get("title") or "",
            "size": e.get("size"),
            "last_probe": e.get("last_probe"),
        })

    # rapikan edges (hanya antar kept nodes)
    kept_ids = {n["id"] for n in nodes}
    edges = [e for e in edges if e["source"] in kept_ids and e["target"] in kept_ids]

    payload = {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "scope": scope,
            "q": q,
            "limit_ips": limit_ips,
            "limit_hosts_per_ip": limit_hosts_per_ip,
            "min_hosts": min_hosts,
        }
    }
    return JSONResponse(payload)
