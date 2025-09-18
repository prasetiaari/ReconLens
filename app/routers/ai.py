# app/routers/ai.py
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict

from fastapi import APIRouter, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from collections import Counter
from urllib.parse import urlparse
# === ikuti pola targets.py ===
from ..deps import get_settings, get_templates
from ..services.ai_analyzer import run_ai_classification  # if routers and services are in same package adjust path: from ..services.ai_analyzer import ...
#hapus filenya from ..services.ai_rules import apply_rules, preview_rules
from pathlib import Path
from ..services.ai_apply import apply_rules, ApplyOptions
from markupsafe import escape

from ..services.llm_provider import OllamaProvider

try:
    # relative import (normal)
    from ..services.ai_rulegen import generate_rules_from_samples
except Exception:
    # absolute fallback (kalau Python path/packaging beda)
    from app.services.ai_rulegen import generate_rules_from_samples  # type: ignore


router = APIRouter()


def _safe_json(path: Path) -> Dict:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _outputs_root(request: Request) -> Path:
    settings = get_settings(request)
    return Path(settings.OUTPUTS_DIR)

@router.post("/{scope}/ai/generate_rules")
async def ai_generate_rules(
    request: Request,
    scope: str,
    sample: int = 100,
    model: str = "llama3.2:3b",
    timeout: int = 90,
    temperature: float = 0.3,
    retries: int = 1,
):
    outputs_root = Path(get_settings(request).OUTPUTS_DIR)
    res = generate_rules_from_samples(
        outputs_root, scope,
        sample_size=sample,
        model=model,
        timeout=timeout,
        temperature=temperature,
        retries=retries,
    )

    # Jika dipanggil dari htmx → balas HTML kecil buat disisipkan ke target
    if request.headers.get("HX-Request"):
        if res.get("ok"):
            msg = (
                f"✅ Generated <b>{res.get('rules_count', 0)}</b> rule(s) "
                f"→ saved to <code>{escape(res.get('path',''))}</code>"
            )
            return HTMLResponse(f"<div class='text-emerald-700'>{msg}</div>")
        else:
            err = escape(res.get("error", "unknown error"))
            return HTMLResponse(f"<div class='text-rose-700'>❌ {err}</div>", status_code=400)

    # fallback biasa (non-htmx): tetap JSON
    return JSONResponse(res)
    
# app/routers/ai.py

# app/routers/ai.py

@router.post("/{scope}/ai/apply_rules")
async def ai_apply_rules(
    request: Request,
    scope: str,
    source: str = Query("seed", description="seed | custom | ai | hybrid"),
    demote_if_no_code: int = Query(1, description="1/0"),
    sample_limit: int = Query(500, ge=1, le=5000),
):
    """Apply selected rules and write ai_classify.json for the UI."""
    settings = get_settings(request)
    outputs_root = Path(settings.OUTPUTS_DIR)

    src = (source or "seed").lower().strip()
    if src == "hybrid":
        sources = ["seed", "custom", "ai"]
    elif src in ("seed", "custom", "ai"):
        sources = [src]
    else:
        return JSONResponse({"ok": False, "error": f"unknown source '{source}'"}, status_code=400)

    opts = ApplyOptions(
        demote_if_no_code=bool(demote_if_no_code),
        sample_limit=sample_limit,   # NOTE: this matches ApplyOptions.sample_limit
    )

    result = apply_rules(outputs_root, scope, sources=sources, options=opts)
    # If you want the page to reload (htmx), just return a tiny ok payload.
    return JSONResponse(result)
    
# --- Health ---
@router.get("/{scope}/ai/provider/health")
async def ai_provider_health(request: Request, scope: str):
    prov = OllamaProvider()
    h = prov.health()
    return {"ok": h.ok, "model": h.model, "detail": h.detail}
'''
# --- Preview LLM (k kecil) ---
@router.get("/{scope}/ai/preview_llm")
async def ai_preview_llm(request: Request, scope: str, k: int = 200, batch: int = 30):
    outputs_root = _outputs_root(request)
    prov = OllamaProvider()
    # pilih kandidat hemat via rules
    candidates = select_candidates_with_rules(outputs_root, scope, top_k=max(1, min(k, 1000)))
    labels = classify_with_llm(outputs_root, scope, prov, candidates, batch_size=max(5, min(batch, 50)))
    # gabung rules + LLM, tapi JANGAN timpa file utama → save_result=False
    merged = merge_rules_and_llm(outputs_root, scope, labels, save_result=False)
    return JSONResponse(merged)
'''
# --- Run LLM (top-K kandidat), simpan ke ai_classify.json ---
@router.post("/{scope}/ai/run_llm")
async def ai_run_llm(request: Request, scope: str, k: int = 500, batch: int = 30):
    outputs_root = _outputs_root(request)
    prov = OllamaProvider()
    candidates = select_candidates_with_rules(outputs_root, scope, top_k=max(1, min(k, 5000)))
    labels = classify_with_llm(outputs_root, scope, prov, candidates, batch_size=max(5, min(batch, 50)))
    merged = merge_rules_and_llm(outputs_root, scope, labels, save_result=True)
    return JSONResponse({"ok": True, "saved": True, "summary": merged.get("summary", {}), "count": len(merged.get("results", []))})
    
@router.get("/{scope}/ai/apply_seed")
async def ai_apply_seed(request: Request, scope: str):
    settings = get_settings(request)
    outputs_root = Path(settings.OUTPUTS_DIR)
    out = apply_rules(outputs_root, scope, save_result=True)
    return JSONResponse(out)

@router.get("/{scope}/ai/preview")
async def ai_preview(request: Request, scope: str, limit: int = 500,
                     demote_blocked: int = 1, demote_404: int = 1):
    """
    Preview dampak rules terhadap subset URL.
    """
    settings = get_settings(request)
    outputs_root = Path(settings.OUTPUTS_DIR)
    out = preview_rules(
        outputs_root, scope,
        limit=max(1, min(limit, 2000)),
        demote_blocked=bool(demote_blocked),
        demote_404=bool(demote_404),
    )
    return JSONResponse(out)
    
@router.post("/{scope}/ai/classify", response_class=HTMLResponse)
async def ai_classify(request: Request, scope: str):
    settings  = get_settings(request)
    templates = get_templates(request)
    outputs_root = Path(getattr(settings, "OUTPUTS_DIR", os.environ.get("OUTPUTS_DIR","outputs"))).resolve()

    res = run_ai_classification(outputs_root, scope, model_hint=os.environ.get("AI_MODEL"))
    ctx = {
        "request": request,
        "scope": scope,
        "ai_summary": res.get("summary") or {},
        "ai_results": res.get("results") or [],
    }
    return templates.TemplateResponse("_ai_classify_panel.html", ctx)

@router.get("/{scope}/ai/classify", response_class=HTMLResponse)
async def ai_classify_get(request: Request, scope: str):
    # GET alias supaya bisa diakses langsung dari browser
    return await ai_classify(request, scope)

# === AI OVERVIEW (landing) ===
@router.get("/{scope}/ai", response_class=HTMLResponse)
async def ai_overview(request: Request, scope: str):
    settings   = get_settings(request)
    templates  = get_templates(request)
    outputs    = Path(settings.OUTPUTS_DIR)
    cache_dir  = outputs / scope / "__cache"
    data_path  = cache_dir / "ai_classify.json"

    ai_summary = {}
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    rules_version = "seed"

    if data_path.exists():
        try:
            data = json.loads(data_path.read_text(encoding="utf-8"))
            ai_summary = data.get("summary") or {}
            counts = ai_summary.get("counts") or counts
            rules_version = ai_summary.get("rules_version") or rules_version
        except Exception as e:
            ai_summary = {"note": f"Failed to parse ai_classify.json: {e}"}

    ctx = {
        "request": request,
        "scope": scope,
        "counts": counts,
        "rules_version": rules_version,
        "summary": ai_summary,
        "page_url": f"/targets/{scope}/ai",   # basis pager kalau nanti dibutuhkan
        "active_ai_tab": "overview",
    }
    return templates.TemplateResponse("ai_overview.html", ctx)
    
@router.get("/{scope}/ai/insights", response_class=HTMLResponse)
async def ai_dashboard(request: Request, scope: str):
    settings   = get_settings(request)
    templates  = get_templates(request)
    outputs    = Path(settings.OUTPUTS_DIR)
    cache_dir  = outputs / scope / "__cache"
    data_path  = cache_dir / "ai_classify.json"

    # --- query params ---
    severity   = (request.query_params.get("severity") or "ALL").upper()
    try:
        page      = int(request.query_params.get("page") or 1)
    except Exception:
        page      = 1
    try:
        page_size = int(request.query_params.get("page_size") or 50)
    except Exception:
        page_size = 50
    if page_size <= 0:
        page_size = 50

    # --- load data ---
    ai_summary: dict = {}
    raw_results: list[dict] = []
    if data_path.exists():
        try:
            data = json.loads(data_path.read_text(encoding="utf-8"))
            ai_summary = data.get("summary") or {}
            raw_results = data.get("results") or data.get("results_sample") or []
        except Exception as e:
            ai_summary = {"note": f"Failed to parse ai_classify.json: {e}"}
            raw_results = []

    counts = ai_summary.get("counts") or {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    model  = ai_summary.get("model") or ai_summary.get("rules_version") or "-"
    rules  = ai_summary.get("rules_version") or "seed"

    # --- filter by severity ---
    valid_sev = {"HIGH", "MEDIUM", "LOW", "INFO"}
    if severity in valid_sev:
        def pick_label(r: dict) -> str:
            return (r.get("final_label") or r.get("label") or r.get("severity") or "-").upper()
        filtered = [r for r in raw_results if pick_label(r) == severity]
    else:
        severity = "ALL"
        filtered = raw_results

    # --- normalize for table ---
    norm_rows: list[dict] = []
    for r in filtered:
        label  = (r.get("final_label") or r.get("label") or r.get("severity") or "-").upper()
        reason = r.get("reason") or r.get("rule") or r.get("why") or "-"
        url    = r.get("url") or r.get("open_url") or r.get("target") or "-"
        norm_rows.append({"url": url, "label": label, "reason": reason})

    # --- paging ---
    total        = len(norm_rows)
    total_pages  = max(1, (total + page_size - 1) // page_size)
    if page > total_pages: page = total_pages
    if page < 1: page = 1
    start = (page - 1) * page_size
    end   = start + page_size
    page_rows = norm_rows[start:end]

    ctx = {
        "request": request,
        "scope": scope,

        # summary
        "ai_summary": ai_summary,
        "counts": counts,
        "rules_version": rules,
        "model": model,

        # table data
        "ai_results": page_rows,   # new data name
        "rows": page_rows,         # <-- alias so template renders
        # pager state
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "pages": total_pages,      # <-- alias some partials expect
        "page_url": f"/targets/{scope}/ai/insights",

        # filters
        "severity": severity,
    }
    return templates.TemplateResponse("ai_insights.html", ctx)
    

def _summarize_status(urls_map: dict) -> dict:
    c = Counter()
    for _, rec in (urls_map or {}).items():
        try:
            code = int(rec.get("code")) if rec and rec.get("code") is not None else None
        except Exception:
            code = None
        if code is None:
            c["nx"] += 1   # not probed / unknown
        else:
            bucket = f"{code//100}xx"
            c[bucket] += 1
    total = sum(c.values()) or 1
    pct = {k: round(v*100/total, 1) for k, v in c.items()}
    return {"counts": dict(c), "pct": pct, "total": total}

def _top_hosts_by_2xx(urls_map: dict, top_n: int = 8) -> list[tuple[str, int]]:
    per_host = Counter()
    for url, rec in (urls_map or {}).items():
        try:
            code = int(rec.get("code")) if rec and rec.get("code") is not None else None
        except Exception:
            code = None
        if code and 200 <= code < 300:
            try:
                host = urlparse(url).netloc.lower()
            except Exception:
                host = ""
            if host:
                per_host[host] += 1
    return per_host.most_common(top_n)

def _collect_ai_context(outputs_root: Path, scope: str) -> dict:
    scope_dir = outputs_root / scope
    cache_dir = scope_dir / "__cache"
    subdomains = _safe_json(cache_dir / "subdomains_enrich.json")
    urls_map   = _safe_json(cache_dir / "url_enrich.json")

    alive_hosts = [h for h, rec in (subdomains or {}).items() if isinstance(rec, dict) and rec.get("alive") is True]
    suspicious_exts = (".zip", ".gz", ".rar", ".7z", ".bak", ".sql", ".tar", ".tar.gz", ".git", ".env", ".old")
    suspicious_urls = [
        u for u in (urls_map or {}).keys()
        if isinstance(u, str) and u.lower().endswith(suspicious_exts)
    ]

    status_summary = _summarize_status(urls_map)
    top2xx_hosts   = _top_hosts_by_2xx(urls_map, top_n=8)

    return {
        "url_count": len(urls_map or {}),
        "alive_count": len(alive_hosts),
        "suspicious_urls": suspicious_urls[:50],   # batasi buat panel
        "suspicious_count": len(suspicious_urls),
        "status_summary": status_summary,
        "top2xx_hosts": top2xx_hosts,
    }

@router.post("/{scope}/ai/insights", response_class=HTMLResponse)
async def ai_generate_insights(request: Request, scope: str):
    """
    Phase-1: generate insights sederhana (tanpa LLM). Return partial HTML panel.
    Nanti endpoint ini tinggal dipasangi LLM kalau mau.
    """
    settings  = get_settings(request)
    templates = get_templates(request)
    outputs_root = Path(getattr(settings, "OUTPUTS_DIR", os.environ.get("OUTPUTS_DIR", "outputs"))).resolve()

    scope_dir = outputs_root / scope
    if not scope_dir.exists():
        raise HTTPException(status_code=404, detail=f"Scope '{scope}' not found")

    ctx = _collect_ai_context(outputs_root, scope)
    ctx.update({
        "request": request,
        "scope": scope,
    })
    # return partial template (panel)
    return templates.TemplateResponse("_ai_insights_panel.html", ctx)
