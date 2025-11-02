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

from .utils import gather_stats, all_hosts_for_scope
from .utils import (
    fmt_last_probe,
    fmt_size_human,
    load_url_enrich,
)
from app.routers.targets.helpers import gather_stats
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

    total_lines = sum((s.get("lines") or 0) for s in stats)
    stats_map = {row["module"]: row for row in stats}

    ctx = {
        "request": request,
        "scope": scope,
        "stats": stats,
        "urls_count": urls_count,
        "stats_map": stats_map,
        "dash": dash,
        "has_modules": total_lines > 0,
        "has_timeago": True,
    }

    templates = get_templates(request)
    return templates.TemplateResponse("target_detail.html", ctx)


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
    codes_str  = (request.query_params.get("codes") or "").strip()
    ctype_sub  = (request.query_params.get("ctype") or "").strip().lower()
    scheme_f   = (request.query_params.get("scheme") or "").strip().lower()
    host_f     = (request.query_params.get("host") or "").strip().lower()
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

    # --- load corpus (+ apply q) & build host options for dropdown ---
    raw_items: list[str] = []
    host_options_set: set[str] = set()
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            s = (ln or "").strip()
            if not s:
                continue
            if q and q.lower() not in s.lower():   # <-- apply substring search
                continue
            raw_items.append(s)
            # collect host options from module file
            try:
                p = urlparse(s)
                if p.netloc:
                    host_options_set.add(p.netloc.lower())
            except Exception:
                pass
    host_options = sorted(host_options_set)

    # --- enrich caches ---
    enrich_host = load_enrich(outputs_root, scope) or {}
    enrich_url  = load_url_enrich(outputs_root, scope) or {}
    discovery_host_options = all_hosts_for_scope(outputs_root, scope)
    wordlists = list_wordlists()

    def pick(*vals):
        for v in vals:
            if v not in (None, "", "-", "None"):
                return v
        return None

    # --- filtering loop (before pagination) ---
    filtered_rows: list[dict] = []
    for s in raw_items:
        try:
            p = urlparse(s)
        except Exception:
            p = None

        host = (p.netloc.lower() if p else "")
        if host_f and host != host_f:
            continue

        rec_host = enrich_host.get(host) if host else None
        rec_url  = (
            enrich_url.get(s)
            or (enrich_url.get(s.rstrip("/")) if s.endswith("/") else None)
            or enrich_url.get(s + "/")
        )

        scheme = (
            (rec_url.get("scheme") if rec_url else None)
            or (rec_host.get("scheme") if rec_host else None)
            or (p.scheme if p else "https")
        )
        if scheme_f and scheme_f not in ("", "(any)", "any"):
            if scheme != scheme_f:
                continue

        method_val = pick(
            rec_url.get("method") if rec_url else None,
            rec_url.get("mode")   if rec_url else None,
            rec_host.get("method") if rec_host else None,
            rec_host.get("mode")   if rec_host else None,
        )
        method_val_u = (str(method_val).upper() if method_val else "")
        if method_filter and method_val_u != method_filter:
            continue

        code  = pick(rec_url.get("code") if rec_url else None,
                     rec_host.get("code") if rec_host else None)
        size  = pick(rec_url.get("size") if rec_url else None,
                     rec_host.get("size") if rec_host else None)
        title = pick(rec_url.get("title") if rec_url else None,
                     rec_host.get("title") if rec_host else None)
        ctype = pick(rec_url.get("content_type") if rec_url else None,
                     rec_host.get("content_type") if rec_host else None)
        lastp = pick(rec_url.get("last_probe") if rec_url else None,
                     rec_host.get("last_probe") if rec_host else None)

        try: code_i = int(code) if code is not None else None
        except: code_i = None
        try: size_i = int(size) if size is not None else None
        except: size_i = None

        # code / class filters
        if codes_set and (code_i not in codes_set):
            continue
        if http_class in ("2xx","3xx","4xx","5xx"):
            if code_i is None or (code_i // 100) != int(http_class[0]):
                continue
        # ctype substring
        if ctype_sub and (not ctype or ctype_sub not in str(ctype).lower()):
            continue
        # size filters
        if min_size is not None and (size_i is None or size_i < min_size):
            continue
        if max_size is not None and (size_i is None or size_i > max_size):
            continue

        final = s
        if p and not p.scheme and scheme:
            final = f"{scheme}://{host}{p.path or '/'}"
            if p.query:
                final += f"?{p.query}"
            if p.fragment:
                final += f"#{p.fragment}"

        alive = (
            rec_url.get("alive") if (rec_url and "alive" in rec_url) else
            (rec_host.get("alive") if (rec_host and "alive" in rec_host) else None)
        )
        status = "up" if alive is True else ("down" if alive is False else "-")

        filtered_rows.append({
            "url": s,
            "open_url": final,
            "status": status,
            "code": code_i,
            "size": fmt_size_human(size_i),
            "title": title,
            "content_type": ctype,
            "last_probe": fmt_last_probe(lastp),
            "host": host,
            "scheme": scheme,
            "method": method_val_u or None,
        })

    # --- pagination ---
    total = len(filtered_rows)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, total_pages)
    start = (page - 1) * page_size
    end   = start + page_size
    rows  = filtered_rows[start:end]

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
    return templates.TemplateResponse("module_generic.html", ctx)

@router.get("/{scope}/probe/module/{module}", response_class=HTMLResponse)
async def probe_module_console_alias(request: Request, scope: str, module: str):
    return RedirectResponse(url=f"/targets/{scope}/collect/probe_module?module={module}")

@router.post("/{scope}/probe/module/{module}/start")
async def probe_module_start_alias(scope: str, module: str, request: Request):
    return RedirectResponse(
        url=f"/targets/{scope}/collect/probe_module/start?module={module}",
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
        "_confirm_delete.html",
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