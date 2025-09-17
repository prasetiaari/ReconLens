# app/routers/ai.py
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

# === ikuti pola targets.py ===
from ..deps import get_settings, get_templates

router = APIRouter()


def _safe_json(path: Path) -> Dict:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


@router.get("/{scope}/ai", response_class=HTMLResponse)
async def ai_dashboard(request: Request, scope: str):
    """
    AI Insights (phase 1, simple):
    - Baca outputs/<scope>/__cache/subdomains_enrich.json & url_enrich.json
    - Tampilkan ringkasan dasar.
    """
    settings = get_settings(request)
    templates = get_templates(request)

    # OUTPUTS_DIR mengikuti env/setting yang sama dipakai targets.py
    outputs_root = Path(getattr(settings, "OUTPUTS_DIR", os.environ.get("OUTPUTS_DIR", "outputs"))).resolve()
    scope_dir = outputs_root / scope
    cache_dir = scope_dir / "__cache"

    if not scope_dir.exists():
        raise HTTPException(status_code=404, detail=f"Scope '{scope}' not found")

    subdomains = _safe_json(cache_dir / "subdomains_enrich.json")
    urls_map = _safe_json(cache_dir / "url_enrich.json")

    # Metrics sederhana
    alive_hosts = [h for h, rec in subdomains.items() if isinstance(rec, dict) and rec.get("alive") is True]

    suspicious_exts = (".zip", ".gz", ".rar", ".7z", ".bak", ".sql", ".tar", ".tar.gz", ".git")
    suspicious_urls = [
        u for u in urls_map.keys()
        if isinstance(u, str) and u.lower().endswith(suspicious_exts)
    ]

    ctx = {
        "request": request,
        "scope": scope,
        "url_count": len(urls_map),
        "alive_count": len(alive_hosts),
        "suspicious_count": len(suspicious_urls),
        "suspicious_urls": suspicious_urls[:10],
    }
    return templates.TemplateResponse("ai_dashboard.html", ctx)
