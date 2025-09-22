# app/routers/settings.py
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Any, Dict, List
from ..deps import get_templates
from app.core.config_store import load_settings, save_settings

router = APIRouter(tags=["settings"])


# -------------------------
# Utilities
# -------------------------
def _as_bool(v, default=False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    return s in ("1", "true", "on", "yes", "y")


def _as_int(v, default=0) -> int:
    try:
        if v is None:
            return default
        return int(str(v).strip())
    except Exception:
        return default


def _saved_fragment(ok: bool, errs: List[str] | None = None, wants_json: bool = False):
    """
    Kembalikan frag HTML 'Saved.' untuk htmx, plus HX-Trigger agar bisa tampil toast global.
    Jika client minta JSON, kirim JSON.
    """
    if wants_json:
        return JSONResponse({"ok": ok, "errors": errs or []}, status_code=200 if ok else 400)

    headers = {"HX-Trigger": '{"settings-saved": true}'}
    if ok:
        return HTMLResponse('<span class="text-emerald-600">Saved.</span>', headers=headers)
    msg = "<ul class='text-sm text-rose-700'>" + "".join(f"<li>• {e}</li>" for e in (errs or ["Save failed"])) + "</ul>"
    return HTMLResponse(msg, status_code=400, headers=headers)


def _ensure_nested(d: Dict[str, Any], path: List[str]) -> Dict[str, Any]:
    cur = d
    for key in path:
        if key not in cur or not isinstance(cur[key], dict):
            cur[key] = {}
        cur = cur[key]
    return cur


# -------------------------
# Page
# -------------------------
@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    T = get_templates(request)
    settings = load_settings() or {}
    return T.TemplateResponse("settings.html", {"request": request, "settings": settings})


# -------------------------
# Section: General HTTP
# -------------------------
@router.post("/settings/http", response_class=HTMLResponse)
async def settings_http(request: Request):
    form = await request.form()
    wants_json = "application/json" in (request.headers.get("accept") or "")

    ua_mode = form.get("ua_mode", "default")
    ua_custom = form.get("ua_custom", "") if ua_mode == "custom" else ""
    timeout = _as_int(form.get("timeout"), 10)
    concurrency = _as_int(form.get("concurrency"), 20)

    keys = form.getlist("headers_key")
    vals = form.getlist("headers_val")
    headers: List[Dict[str, str]] = []
    for i, k in enumerate(keys or []):
        k = (k or "").strip()
        v = (vals[i] if i < len(vals) else "") or ""
        if k:
            headers.append({"key": k, "value": v})

    proxy_enabled = _as_bool(form.get("proxy_enabled"), False)
    proxy_url = (form.get("proxy_url") or "").strip() if proxy_enabled else ""

    settings = load_settings() or {}
    http = _ensure_nested(settings, ["http"])
    http["user_agent"] = {"mode": ua_mode, "value": ua_custom}
    http["timeout"] = timeout
    http["concurrency"] = concurrency
    http["headers"] = headers
    http["proxy"] = {"enabled": proxy_enabled, "url": proxy_url}

    ok, errs = save_settings(settings)
    return _saved_fragment(ok, errs, wants_json)


# -------------------------
# Section: Tools / Tooling
# -------------------------
@router.post("/settings/tooling", response_class=HTMLResponse)
async def settings_tooling(request: Request):
    form = await request.form()
    wants_json = "application/json" in (request.headers.get("accept") or "")

    tools = {
        "urlscan_api": (form.get("urlscan_api") or "").strip(),
        "virustotal_api": (form.get("virustotal_api") or "").strip(),
        "waymore_sources": (form.get("waymore_sources") or "").strip(),
        "urls_limit": _as_int(form.get("urls_limit"), 0),
        "dirsearch_wordlist": (form.get("dirsearch_wordlist") or "").strip(),
        "dirsearch_ext": (form.get("dirsearch_ext") or "").strip(),
        "prefer_https": _as_bool(form.get("prefer_https"), True),
        "if_head_then_get": _as_bool(form.get("if_head_then_get"), True),
        "delay_ms": _as_int(form.get("delay_ms"), 0),
    }

    settings = load_settings() or {}
    settings["tools"] = tools
    ok, errs = save_settings(settings)
    return _saved_fragment(ok, errs, wants_json)


# -------------------------
# Section: UI
# -------------------------
@router.post("/settings/ui", response_class=HTMLResponse)
async def settings_ui(request: Request):
    form = await request.form()
    wants_json = "application/json" in (request.headers.get("accept") or "")

    theme = form.get("theme", "light")
    retention_days = _as_int(form.get("retention_days"), 0)

    settings = load_settings() or {}
    ui = _ensure_nested(settings, ["ui"])
    ui["theme"] = theme
    ui["retention_days"] = retention_days

    ok, errs = save_settings(settings)
    return _saved_fragment(ok, errs, wants_json)


# -------------------------
# Section: AI
# -------------------------
@router.post("/settings/ai", response_class=HTMLResponse)
async def settings_ai(request: Request):
    form = await request.form()
    wants_json = "application/json" in (request.headers.get("accept") or "")

    model = form.get("ai_model", "llama3.2:3b")
    autorun = _as_bool(form.get("ai_autorun"), False)

    settings = load_settings() or {}
    ai = _ensure_nested(settings, ["ai"])
    ai["model"] = model
    ai["autorun"] = autorun

    ok, errs = save_settings(settings)
    return _saved_fragment(ok, errs, wants_json)


# -------------------------
# Legacy bulk (opsional)
# -------------------------
@router.post("/settings/save", response_class=HTMLResponse)
async def settings_save(request: Request):
    wants_json = "application/json" in (request.headers.get("accept") or "")
    try:
        data = await request.json()
        if not isinstance(data, dict):
            raise ValueError("Invalid JSON")
    except Exception:
        return _saved_fragment(False, ["Invalid JSON payload."], wants_json)

    settings = load_settings() or {}
    for k, v in data.items():
        if isinstance(v, dict):
            settings[k] = v
    ok, errs = save_settings(settings)
    return _saved_fragment(ok, errs, wants_json)
