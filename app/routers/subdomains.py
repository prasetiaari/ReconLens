from __future__ import annotations
import math
from pathlib import Path
from fastapi import APIRouter, Request
from app.core.settings import get_settings
from app.core.templates import get_templates
from app.core.fs import iter_lines
from datetime import datetime, timezone
from typing import Any
from fastapi.responses import HTMLResponse


from app.services.enrich_subdomains import get_probe_map_cached as load_enrich
router = APIRouter()

def _coerce_ts(value: Any) -> datetime | None:
    """
    Terima epoch int/str, atau ISO string (dengan/ tanpa 'Z'), kembalikan datetime UTC.
    """
    if value is None:
        return None
    # epoch number
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(int(value), tz=timezone.utc)
        except Exception:
            return None
    # string
    if isinstance(value, str):
        s = value.strip()
        # epoch in string
        if s.isdigit():
            try:
                return datetime.fromtimestamp(int(s), tz=timezone.utc)
            except Exception:
                return None
        # ISO
        try:
            if s.endswith("Z"):
                s = s.replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None
    return None
def _time_ago_from_any(value: Any) -> str:
    dt = _coerce_ts(value)
    if not dt:
        return "-"
    now = datetime.now(timezone.utc)
    delta = (now - dt).total_seconds()
    if delta < 1:
        return "now"
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta//60)}m ago"
    if delta < 86400:
        return f"{int(delta//3600)}h ago"
    return f"{int(delta//86400)}d ago"
    
def _parse_iso(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        # dukung ...Z (UTC) dan offset-aware ISO
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def _time_ago(ts: str) -> str:
    dt = _parse_iso(ts)
    if not dt:
        return "-"
    now = datetime.now(timezone.utc)
    if not dt.tzinfo:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = (now - dt).total_seconds()
    if delta < 1:
        return "now"
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // 86400)}d ago"

def _decorate_last_probe(enrich: dict[str, dict], hosts: list[str]) -> None:
    """
    Mutasi in-memory: set rec['last_probe'] sebagai string 'ago'.
    Ambil sumber dari rec['last_probe'] (epoch/ISO) atau fallback rec['ts'].
    """
    for h in hosts:
        rec = enrich.get(h)
        if not rec:
            continue
        raw = rec.get("last_probe")
        if raw is None:
            raw = rec.get("ts")
        rec["last_probe"] = _time_ago_from_any(raw)
            
def _alive_flag(req: Request) -> bool:
    v = (req.query_params.get("alive") or "").lower()
    return v in ("1", "true", "on", "yes")

def _resolve_subdomains_file(outputs_dir: Path, scope: str, modules_conf) -> Path:
    # modules_conf bisa dict atau list; safe-get
    filename = "subdomains.txt"
    if isinstance(modules_conf, dict):
        mod = modules_conf.get("subdomains")
        if isinstance(mod, dict):
            filename = mod.get("file", filename)
    return outputs_dir / scope / filename

def _iter_hosts_filtered(path: Path, q: str, enrich: dict[str, dict], alive_only: bool):
    if not path.exists():
        return
    for host in iter_lines(path):
        if q and q not in host:
            continue
        if alive_only:
            rec = enrich.get(host)
            if not (rec and rec.get("alive")):
                continue
        yield host

def _paginate_iter(it, page: int, page_size: int):
    start = max(0, (page - 1) * page_size)
    end = start + page_size
    rows, idx = [], 0
    for host in it:
        if idx >= start and idx < end:
            rows.append(host)
        idx += 1
    total = idx
    total_pages = max(1, math.ceil(total / max(1, page_size)))
    has_prev = page > 1
    has_next = page < total_pages
    return rows, total, total_pages, has_prev, has_next

@router.get("/targets/{scope}/subdomains/ip_clusters", response_class=HTMLResponse)
async def subdomains_ip_clusters(scope: str, request: Request):
    settings = get_settings(request)
    templates = get_templates(request)

    # endpoint JSON untuk graph (yang sudah kamu buat di services/…)
    data_url = f"/targets/{scope}/subdomains/ip_clusters.json"

    ctx = {
        "request": request,
        "scope": scope,
        "data_url": data_url,
        "back_url": f"/targets/{scope}/subdomains",
    }
    return templates.TemplateResponse("subdomains_ip_clusters.html", ctx)
    
@router.get("/targets/{scope}/subdomains")
async def subdomains_page(scope: str, request: Request):
    settings = get_settings(request)
    templates = get_templates(request)

    q = request.query_params.get("q") or ""
    page = int(request.query_params.get("page") or 1)
    page_size = int(request.query_params.get("page_size") or 100)
    alive = _alive_flag(request)

    outputs_dir = Path(settings.OUTPUTS_DIR)
    page_url = f"/targets/{scope}/subdomains"

    sub_file = _resolve_subdomains_file(outputs_dir, scope, settings.MODULES)
    enrich = load_enrich(outputs_dir, scope) or {}

    it = _iter_hosts_filtered(sub_file, q, enrich, alive_only=alive)
    rows, total, total_pages, has_prev, has_next = _paginate_iter(it, page, page_size)
    _decorate_last_probe(enrich, rows)
    
    ctx = {
        "request": request,
        "scope": scope,
        "page_url": page_url,
        "q": q,
        "page": page,
        "page_size": page_size,
        "alive": alive,
        "rows": rows,
        "total": total,
        "total_pages": total_pages,
        "has_prev": has_prev,
        "has_next": has_next,
        "enrich": enrich,
    }
    return templates.TemplateResponse("subdomains.html", ctx)

# OPTIONAL: kalau kamu masih butuh endpoint rows-only
@router.get("/targets/{scope}/subdomains/rows")
async def subdomains_rows(scope: str, request: Request):
    settings = get_settings(request)
    templates = get_templates(request)

    q = request.query_params.get("q") or ""
    page = int(request.query_params.get("page") or 1)
    page_size = int(request.query_params.get("page_size") or 100)
    alive = _alive_flag(request)

    outputs_dir = Path(settings.OUTPUTS_DIR)
    page_url = f"/targets/{scope}/subdomains"

    sub_file = _resolve_subdomains_file(outputs_dir, scope, settings.MODULES)
    enrich = load_enrich(outputs_dir, scope) or {}

    it = _iter_hosts_filtered(sub_file, q, enrich, alive_only=alive)
    rows, total, total_pages, has_prev, has_next = _paginate_iter(it, page, page_size)
    _decorate_last_probe(enrich, rows)
    
    # render halaman penuh juga supaya konsisten dengan hx-select="#page"
    ctx = {
        "request": request,
        "scope": scope,
        "page_url": page_url,
        "q": q,
        "page": page,
        "page_size": page_size,
        "alive": alive,
        "rows": rows,
        "total": total,
        "total_pages": total_pages,
        "has_prev": has_prev,
        "has_next": has_next,
        "enrich": enrich,
    }
    return templates.TemplateResponse("subdomains.html", ctx)
