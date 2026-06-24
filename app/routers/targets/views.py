"""
Targets View Routes
-------------------

Serve all HTML pages related to targets and modules.
This module focuses purely on read/view operations.

Dependencies:
    - get_settings()  : global settings from app state
    - get_templates() : shared Jinja2Templates instance
"""

from __future__ import annotations
import re
import shutil, json

from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, Optional

from fastapi import APIRouter, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, Response
from app.deps import get_settings, get_templates
from ..subdomains import subdomains_page, load_enrich
from ...services.wordlists import list_wordlists
from app.services.enrich_urls import canon_url

from .utils import gather_stats, all_hosts_for_scope
from .utils import (
    fmt_last_probe,
    fmt_size_human,
    load_url_enrich,
    gather_stats
)

#from app.routers.targets.helpers import gather_stats
from urllib.parse import urlencode
from fastapi.responses import HTMLResponse, RedirectResponse

router = APIRouter()


@router.get("/{scope}", response_class=HTMLResponse)
async def target_detail(request: Request, scope: str):
    """Render overview page for a given target scope."""
    stats_pack = gather_stats(scope)
    stats = stats_pack["stats"]
    urls_count = stats_pack["urls_count"]
    dash = stats_pack["dash"]
    tool_counts = stats_pack.get("tool_counts", {"gau": 0, "waymore": 0, "urlfinder": 0})

    total_lines = sum((s.get("lines") or 0) for s in stats)
    stats_map = {row["module"]: row for row in stats}

    ctx = {
        "request": request,
        "scope": scope,
        "stats": stats,
        "urls_count": urls_count,
        "stats_map": stats_map,
        "dash": dash,
        "tool_counts": tool_counts,
        "has_modules": total_lines > 0,
        "has_timeago": True,
    }
    #print(ctx)
    templates = get_templates(request)
    return templates.TemplateResponse("targets/overview.html", ctx)


@router.get("/{scope}/{module}", response_class=HTMLResponse)
async def module_view(request: Request, scope: str, module: str, q: str = ""):
    mod = (module or "").strip().lower()
    if mod == "subdomains":
        return await subdomains_page(scope=scope, request=request)

    settings = get_settings(request)
    templates = get_templates(request)
    outputs_root = Path(settings.OUTPUTS_DIR)
    out_dir = outputs_root / scope
    path = out_dir / f"{mod}.txt"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Module file not found")

    # --- query params ---
    page       = int(request.query_params.get("page") or 1)
    page_size  = int(request.query_params.get("page_size") or 50)
    if page_size < 1:
        page_size = 50

    http_class = (request.query_params.get("http_class") or "").strip().lower()
    if http_class in ("(any)", "any"): http_class = ""
        
    codes_str  = (request.query_params.get("codes") or "").strip()
    ctype_sub  = (request.query_params.get("ctype") or "").strip().lower()
    
    scheme_f   = (request.query_params.get("scheme") or "").strip().lower()
    if scheme_f in ("(any)", "any"): scheme_f = ""
        
    host_f     = (request.query_params.get("host") or "").strip().lower()
    if host_f in ("(any)", "any"): host_f = ""
        
    method_filter = (request.query_params.get("method") or "").strip().upper()
    if method_filter in ("(ANY)", "ANY"):
        method_filter = ""

    # NEW: safe ints for size filters
    def _to_int(val):
        try:
            return int(val) if (val is not None and str(val).strip() != "") else None
        except Exception:
            return None
    min_size = _to_int(request.query_params.get("min_size"))
    max_size = _to_int(request.query_params.get("max_size"))

    # codes -> set[int]
    codes_set = set()
    if codes_str:
        for tok in codes_str.replace(";", ",").split(","):
            tok = tok.strip()
            if tok.isdigit():
                codes_set.add(int(tok))

    # --- enrich caches ---
    discovery_host_options = all_hosts_for_scope(outputs_root, scope)
    wordlists = list_wordlists()

    # --- SQLite Database Sync and Query ---
    from app.services.db_sync import sync_target, get_db_path
    import sqlite3
    
    # Ensure DB is synced (very fast if unchanged)
    sync_target(outputs_root, scope)
    
    db_path = get_db_path(outputs_root, scope)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    query_parts = ["FROM module_urls u LEFT JOIN enrich_data e ON u.url = e.url WHERE u.module = ?"]
    params = [mod]

    if q:
        query_parts.append("AND u.url LIKE ?")
        params.append(f"%{q}%")
    if host_f:
        query_parts.append("AND e.host = ?")
        params.append(host_f)
    if scheme_f:
        query_parts.append("AND u.url LIKE ?")
        params.append(f"{scheme_f}://%")
    if codes_set:
        placeholders = ','.join('?' for _ in codes_set)
        query_parts.append(f"AND e.code IN ({placeholders})")
        params.extend(codes_set)
    elif http_class in ("2xx", "3xx", "4xx", "5xx"):
        cls_int = int(http_class[0])
        query_parts.append("AND e.code >= ? AND e.code < ?")
        params.extend([cls_int * 100, (cls_int + 1) * 100])
    if ctype_sub:
        query_parts.append("AND e.content_type LIKE ?")
        params.append(f"%{ctype_sub}%")
    if min_size is not None:
        query_parts.append("AND e.size >= ?")
        params.append(min_size)
    if max_size is not None:
        query_parts.append("AND e.size <= ?")
        params.append(max_size)
    if method_filter:
        query_parts.append("AND (e.method = ? OR e.supported_methods LIKE ?)")
        params.extend([method_filter, f'%"{method_filter}"%'])

    base_query = " ".join(query_parts)

    # Get total count for pagination
    cur.execute(f"SELECT COUNT(*) {base_query}", params)
    total = cur.fetchone()[0]

    # Pagination logic
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, total_pages)
    start = (page - 1) * page_size

    # Fetch rows
    cur.execute(f"SELECT u.url, e.host, e.code, e.size, e.title, e.content_type, e.method, e.supported_methods, e.last_probe, e.alive {base_query} LIMIT ? OFFSET ?", params + [page_size, start])
    db_rows = cur.fetchall()

    filtered_rows = []
    for row in db_rows:
        try:
            supp = json.loads(row["supported_methods"]) if row["supported_methods"] else []
        except Exception:
            supp = []

        status = "alive" if row["alive"] == 1 else ("dead" if row["alive"] == 0 else "-")
        # Extract scheme safely
        url_val = row["url"]
        scheme_val = ""
        try:
            if "://" in url_val:
                scheme_val = url_val.split("://")[0]
        except Exception:
            pass

        filtered_rows.append({
            "url": url_val,
            "open_url": url_val,
            "status": status,
            "code": row["code"],
            "size": fmt_size_human(row["size"]),
            "title": row["title"],
            "content_type": row["content_type"],
            "last_probe": fmt_last_probe(row["last_probe"]),
            "host": row["host"],
            "scheme": scheme_val,
            "method": row["method"],
            "supported_methods": supp,
        })

    conn.close()
    rows = filtered_rows

    stats_pack = gather_stats(scope)
    stats = stats_pack["stats"]
    stats_map = {row["module"]: row for row in stats}

    # build persistent qs for pager
    from urllib.parse import urlencode
    extra_qs_params = {
        "q": q or "",
        "http_class": http_class or "(any)",
        "method": method_filter or "(any)",
        "codes": codes_str or "",
        "ctype": ctype_sub or "",
        "min_size": "" if min_size is None else str(min_size),
        "max_size": "" if max_size is None else str(max_size),
        "scheme": scheme_f or "(any)",
        "host": host_f or "",
    }
    extra_qs = "&" + urlencode(extra_qs_params)

    host_options = discovery_host_options

    ctx = {
        "request": request,
        "scope": scope,
        "module": mod,
        "rows": rows,
        "q": q,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "stats": stats,
        "stats_map": stats_map,
        "method_filter": method_filter or "(any)",
        "http_class": http_class or "(any)",
        "codes": codes_str,
        "ctype": ctype_sub,
        "scheme": scheme_f or "(any)",
        "host": host_f,
        "host_filter": host_f,           # <-- expected by templates
        "host_options": host_options,    # <-- fill dropdown from file
        "discovery_host_options": discovery_host_options,  # keep this too
        "wordlists": wordlists,
        "limit": page_size,
        "page_url": f"/targets/{scope}/{mod}",
        "extra_qs": extra_qs,
    }
    # backward compatibility for pager
    ctx["pages"] = ctx.get("total_pages", 1)
    return templates.TemplateResponse("targets/module_generic.html", ctx)

@router.get("/{scope}/probe/module/{module}", response_class=HTMLResponse)
async def probe_module_console_alias(request: Request, scope: str, module: str):
    qs = request.url.query
    return RedirectResponse(url=f"/targets/{scope}/collect/probe_module?module={module}&{qs}")

@router.post("/{scope}/probe/module/{module}/start")
async def probe_module_start_alias(scope: str, module: str, request: Request):
    qs = request.url.query
    return RedirectResponse(
        url=f"/targets/{scope}/collect/probe_module/start?module={module}&{qs}",
        status_code=307
    )

@router.get("/{scope}/delete/confirmation", response_class=HTMLResponse)
async def delete_confirm(request: Request, scope: str):
    templates = get_templates(request)
    outputs_root = Path(get_settings(request).OUTPUTS_DIR)
    scope_path = outputs_root / scope
    if not scope_path.exists():
        return HTMLResponse(
            f"<div class='p-4 text-sm text-rose-600'>Target <code>{scope}</code> not found.</div>",
            status_code=404
        )
    return templates.TemplateResponse(
        "targets/partials/_confirm_delete.html",
        {"request": request, "scope": scope}
    )

@router.post("/{scope}/delete/confirmed", response_class=HTMLResponse)
async def delete_hard(request: Request, scope: str, confirm: str = Form(...)):
    outputs_root = Path(get_settings(request).OUTPUTS_DIR)
    scope_path = outputs_root / scope

    if confirm.strip() != scope:
        return HTMLResponse(
            "<div class='p-3 text-sm text-rose-600'>Confirmation does not match.</div>",
            status_code=400
        )

    try:
        if scope_path.exists():
            shutil.rmtree(scope_path)
        headers = {"HX-Trigger": json.dumps({"target-deleted": {"scope": scope}})}
        return Response("", status_code=204, headers=headers)
    except Exception as e:
        return HTMLResponse(
            f"<div class='p-3 text-sm text-rose-600'>Delete failed: {e}</div>",
            status_code=500
        )