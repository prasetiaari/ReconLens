# app/routers/graphs_subdomains.py
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Iterable

import json
from fastapi.responses import HTMLResponse
from app.core.settings import get_settings
from app.core.templates import get_templates

from fastapi import APIRouter, Request, HTTPException, Query
from fastapi.responses import JSONResponse

from app.core.settings import get_settings

router = APIRouter()


# ---------- helpers ----------

def _cache_dir(outputs_dir: Path, scope: str) -> Path:
    return outputs_dir / scope / "__cache"

def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def _load_ndjson(path: Path) -> List[dict]:
    if not path.exists():
        return []
    out: List[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                # skip broken lines
                continue
    return out

def _epoch_to_iso(ts: Optional[int | float]) -> Optional[str]:
    if ts is None:
        return None
    try:
        import datetime as dt
        return dt.datetime.utcfromtimestamp(float(ts)).replace(microsecond=0).isoformat() + "Z"
    except Exception:
        return None


# ---------- loader: edges + host enrich ----------

def _load_edges(cache_dir: Path) -> List[Tuple[str, str]]:
    """
    Return list of (host, ip).
    Prefer __cache/host_ip_edges.ndjson if exists.
    Fallback: build from subdomains_enrich.json if it has 'ips' per host.
    """
    edges_path = cache_dir / "host_ip_edges.ndjson"
    if edges_path.exists():
        items = _load_ndjson(edges_path)
        edges: List[Tuple[str, str]] = []
        for it in items:
            # support {"host": "...", "ip": "..."} or {"host":"...", "ips":[...]}
            h = it.get("host")
            if not h:
                continue
            if "ip" in it and it["ip"]:
                edges.append((h, it["ip"]))
            elif "ips" in it and isinstance(it["ips"], list):
                for ip in it["ips"]:
                    if ip:
                        edges.append((h, ip))
        return edges

    # fallback from enrich
    enrich_path = cache_dir / "subdomains_enrich.json"
    enrich = _load_json(enrich_path)
    edges: List[Tuple[str, str]] = []
    for host, rec in enrich.items():
        ips = rec.get("ips") if isinstance(rec, dict) else None
        if isinstance(ips, list):
            for ip in ips:
                if ip:
                    edges.append((host, ip))
    return edges


def _load_host_enrich(cache_dir: Path) -> Dict[str, dict]:
    """
    host -> {alive, code, size, title, last_probe/ts, ips, scheme}
    """
    enrich_path = cache_dir / "subdomains_enrich.json"
    data = _load_json(enrich_path)
    if not isinstance(data, dict):
        return {}
    # normalisasi minimal
    out: Dict[str, dict] = {}
    for host, rec in data.items():
        if not isinstance(rec, dict):
            continue
        out[host] = rec
    return out


def _load_rollup(cache_dir: Path) -> Dict[str, dict]:
    """
    Optional: ringkasan per IP (kalau ada).
    Structure bebas; kita pakai kalau ditemukan saja.
    """
    roll_path = cache_dir / "rollup_group_by_ip.json"
    data = _load_json(roll_path)
    return data if isinstance(data, dict) else {}


# ---------- builder: ip-clusters ----------

def _build_ip_clusters(
    outputs_dir: Path,
    scope: str,
    q: Optional[str] = None,
    min_hosts: int = 1,
    limit_ips: Optional[int] = None,
    limit_hosts_per_ip: Optional[int] = None,
) -> dict:
    """
    Return dict: { "nodes": [...], "edges": [...] }
    nodes: {id, type: "ip"/"host", ...}
    edges: {source, target}
    """
    cache_dir = _cache_dir(outputs_dir, scope)
    if not cache_dir.exists():
        raise FileNotFoundError(f"Cache dir not found: {cache_dir}")

    edges = _load_edges(cache_dir)  # [(host, ip), ...]
    if not edges:
        # nothing to render
        return {"nodes": [], "edges": []}

    host_enrich = _load_host_enrich(cache_dir)
    rollup = _load_rollup(cache_dir)
    q_low = (q or "").lower()

    # Build mapping
    ip_to_hosts: Dict[str, Set[str]] = {}
    host_to_ips: Dict[str, Set[str]] = {}

    for host, ip in edges:
        if q_low and q_low not in host.lower():
            continue
        ip_to_hosts.setdefault(ip, set()).add(host)
        host_to_ips.setdefault(host, set()).add(ip)

    # filter ip dengan min_hosts
    ip_list = [(ip, hosts) for ip, hosts in ip_to_hosts.items() if len(hosts) >= max(1, min_hosts)]
    # sort IP by cluster size (desc)
    ip_list.sort(key=lambda t: len(t[1]), reverse=True)

    if limit_ips is not None and limit_ips > 0:
        ip_list = ip_list[:limit_ips]

    nodes: Dict[str, dict] = {}
    edges_out: List[dict] = []

    for ip, hosts in ip_list:
        if limit_hosts_per_ip is not None and limit_hosts_per_ip > 0:
            # stabil: sort host names asc, pick first N
            hosts = sorted(hosts)[:limit_hosts_per_ip]
        else:
            hosts = sorted(hosts)

        # summary untuk IP node
        alive_count = 0
        last_ts: Optional[float] = None
        for h in hosts:
            rec = host_enrich.get(h) or {}
            if rec.get("alive"):
                alive_count += 1
            ts = rec.get("last_probe") or rec.get("ts")
            try:
                ts = float(ts) if ts is not None else None
            except Exception:
                ts = None
            if ts is not None:
                last_ts = max(last_ts or ts, ts)

        # buat IP node
        ip_id = f"ip:{ip}"
        ip_node = {
            "id": ip_id,
            "type": "ip",
            "ip": ip,
            "hosts": len(hosts),
            "alive": alive_count,
            "last_probe": _epoch_to_iso(last_ts) if last_ts else None,
        }

        # merge if exists
        if ip_id not in nodes:
            nodes[ip_id] = ip_node
        else:
            nodes[ip_id].update(ip_node)

        # host nodes + edges
        for h in hosts:
            h_id = f"host:{h}"
            rec = host_enrich.get(h) or {}
            # ambil info dasar
            host_node = {
                "id": h_id,
                "type": "host",
                "host": h,
                "alive": bool(rec.get("alive")),
                "code": rec.get("code"),
                "title": rec.get("title"),
                "scheme": rec.get("scheme"),
                "size": rec.get("size"),
                "last_probe": _epoch_to_iso(rec.get("last_probe") or rec.get("ts")) if (rec.get("last_probe") or rec.get("ts")) else None,
            }
            if h_id not in nodes:
                nodes[h_id] = host_node
            else:
                nodes[h_id].update(host_node)

            edges_out.append({"source": h_id, "target": ip_id})

    # convert to lists
    return {"nodes": list(nodes.values()), "edges": edges_out}


def _build_ip_cluster_for_one(
    outputs_dir: Path,
    scope: str,
    ip: str,
    limit_hosts: Optional[int] = None,
) -> dict:
    """
    Single IP ego graph.
    """
    cache_dir = _cache_dir(outputs_dir, scope)
    if not cache_dir.exists():
        raise FileNotFoundError(f"Cache dir not found: {cache_dir}")

    edges = _load_edges(cache_dir)
    if not edges:
        return {"nodes": [], "edges": []}

    host_enrich = _load_host_enrich(cache_dir)

    hosts: Set[str] = set(h for (h, i) in edges if i == ip)
    if not hosts:
        return {"nodes": [], "edges": []}

    hosts = set(sorted(hosts)[:limit_hosts]) if (limit_hosts and limit_hosts > 0) else hosts

    nodes: Dict[str, dict] = {}
    edges_out: List[dict] = []

    # IP node
    alive_count = 0
    last_ts: Optional[float] = None
    for h in hosts:
        rec = host_enrich.get(h) or {}
        if rec.get("alive"):
            alive_count += 1
        ts = rec.get("last_probe") or rec.get("ts")
        try:
            ts = float(ts) if ts is not None else None
        except Exception:
            ts = None
        if ts is not None:
            last_ts = max(last_ts or ts, ts)

    ip_id = f"ip:{ip}"
    nodes[ip_id] = {
        "id": ip_id,
        "type": "ip",
        "ip": ip,
        "hosts": len(hosts),
        "alive": alive_count,
        "last_probe": _epoch_to_iso(last_ts) if last_ts else None,
    }

    for h in sorted(hosts):
        h_id = f"host:{h}"
        rec = host_enrich.get(h) or {}
        nodes[h_id] = {
            "id": h_id,
            "type": "host",
            "host": h,
            "alive": bool(rec.get("alive")),
            "code": rec.get("code"),
            "title": rec.get("title"),
            "scheme": rec.get("scheme"),
            "size": rec.get("size"),
            "last_probe": _epoch_to_iso(rec.get("last_probe") or rec.get("ts")) if (rec.get("last_probe") or rec.get("ts")) else None,
        }
        edges_out.append({"source": h_id, "target": ip_id})

    return {"nodes": list(nodes.values()), "edges": edges_out}


# ---------- routes ----------

@router.get("/targets/{scope}/graphs/subdomains", response_class=HTMLResponse)
def ip_clusters_page(scope: str, request: Request):
    """
    Halaman HTML yang me-render graph subdomains↔IP.
    """
    settings = get_settings(request)
    templates = get_templates(request)

    # default param UI (boleh diubah dari query)
    q = request.query_params.get("q") or ""
    min_hosts = int(request.query_params.get("min_hosts") or 1)
    limit_ips = int(request.query_params.get("limit_ips") or 200)
    limit_hosts_per_ip = int(request.query_params.get("limit_hosts_per_ip") or 150)

    ctx = {
        "request": request,
        "scope": scope,
        "q": q,
        "min_hosts": min_hosts,
        "limit_ips": limit_ips,
        "limit_hosts_per_ip": limit_hosts_per_ip,
        # base url JSON data:
        "data_url": f"/targets/{scope}/graphs/subdomains/ip-clusters",
        "ego_url_base": f"/targets/{scope}/graphs/subdomains/ip",
    }
    return templates.TemplateResponse("graphs/subdomains.html", ctx)
    
@router.get("/targets/{scope}/graphs/subdomains/ip-clusters", response_class=JSONResponse)
def ip_clusters(
    scope: str,
    request: Request,
    q: str | None = Query(default=None, description="Filter host substring"),
    min_hosts: int = Query(default=1, ge=1),
    limit_ips: int | None = Query(default=200, ge=1),
    limit_hosts_per_ip: int | None = Query(default=150, ge=1),
):
    """
    Graph semua cluster host↔IP untuk scope.
    """
    settings = get_settings(request)
    outputs_dir = Path(settings.OUTPUTS_DIR)

    try:
        data = _build_ip_clusters(
            outputs_dir=outputs_dir,
            scope=scope,
            q=q,
            min_hosts=min_hosts,
            limit_ips=limit_ips,
            limit_hosts_per_ip=limit_hosts_per_ip,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return JSONResponse(data)


@router.get("/targets/{scope}/graphs/subdomains/ip/{ip}", response_class=JSONResponse)
def ip_ego(
    scope: str,
    ip: str,
    request: Request,
    limit_hosts: int | None = Query(default=300, ge=1),
):
    """
    Graph untuk satu IP (ego graph).
    """
    settings = get_settings(request)
    outputs_dir = Path(settings.OUTPUTS_DIR)

    try:
        data = _build_ip_cluster_for_one(
            outputs_dir=outputs_dir,
            scope=scope,
            ip=ip,
            limit_hosts=limit_hosts,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return JSONResponse(data)
