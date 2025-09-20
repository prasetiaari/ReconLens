# app/routers/ai_commands.py
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ..deps import get_settings, get_templates
from .subdomains import load_enrich  # pakai loader yang sudah ada

router = APIRouter(prefix="/targets", tags=["ai"])

# ====== util cache/plan ======
def _cache_dir(outputs_root: Path, scope: str) -> Path:
    d = outputs_root / scope / "__cache" / "ai_jobs"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _plan_path(outputs_root: Path, scope: str) -> Path:
    return _cache_dir(outputs_root, scope) / "plan.json"

def _save_json(p: Path, obj: Any) -> None:
    p.write_text(__import__("json").dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")

def _load_json(p: Path) -> Any:
    import json
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def _get_plan(outputs_root: Path, scope: str) -> Optional[Dict[str, Any]]:
    return _load_json(_plan_path(outputs_root, scope))

# ====== helpers action ======
def _load_subdomains_file(outputs_root: Path, scope: str) -> list[str]:
    p = outputs_root / scope / "subdomains.txt"
    hosts: list[str] = []
    if p.exists():
        for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = (ln or "").strip()
            if s:
                hosts.append(s)
    return hosts

def _list_active_subdomains(outputs_root: Path, scope: str) -> list[str]:
    """
    Prioritas: enrich_host (alive==True). Fallback: semua host dari enrich,
    fallback lagi: subdomains.txt (tanpa filter).
    """
    enrich_host = load_enrich(outputs_root, scope) or {}
    if enrich_host:
        alive_hosts = [h for h, rec in enrich_host.items() if rec and (rec.get("alive") is True)]
        if alive_hosts:
            return sorted(set(alive_hosts))
        return sorted(set(enrich_host.keys()))
    return sorted(set(_load_subdomains_file(outputs_root, scope)))

# ====== ROUTES ======

# Page UI
@router.get("/{scope}/ai/command", response_class=HTMLResponse)
async def ai_command_page(request: Request, scope: str):
    settings = get_settings(request)
    templates = get_templates(request)
    # tidak butuh data khusus untuk tampilan awal
    return templates.TemplateResponse("ai_command.html", {
        "request": request,
        "scope": scope,
        "module": "ai",  # biar tab AI aktif
    })

# Parse prompt -> simpan plan.json
@router.post("/{scope}/ai/command_parse", response_class=HTMLResponse)
async def ai_command_parse(request: Request, scope: str):
    settings = get_settings(request)
    outputs_root = Path(settings.OUTPUTS_DIR)

    form = await request.form()
    prompt = (form.get("prompt") or "").strip()
    intent = (form.get("intent") or "auto").strip().lower()
    model  = (form.get("model")  or "llama3.2:3b").strip()

    if not prompt:
        return HTMLResponse("<div class='text-rose-600 text-sm'>Prompt is required.</div>", status_code=400)

    # Heuristic parser sederhana (bisa diganti LLM nanti)
    actions: List[Dict[str, Any]] = []
    p_low = prompt.lower()

    if "subdomain" in p_low:
        actions.append({"tool": "list_active_subdomains", "args": {}})
    elif "dirsearch" in p_low or "dir search" in p_low:
        actions.append({"tool": "dirsearch", "args": {"host": "__all__", "wordlist": "medium"}})
    else:
        # default: analisa korpus ringan
        actions.append({"tool": "analyze_urls", "args": {"limit": 200}})

    plan = {
        "scope": scope,
        "model": model,
        "intent": intent,
        "prompt": prompt,
        "actions": actions,
    }
    _save_json(_plan_path(outputs_root, scope), plan)

    # Preview HTML sederhana (supaya langsung muncul cantik di panel)
    def _pre(obj: Any) -> str:
        import json
        return json.dumps(obj, ensure_ascii=False, indent=2)

    items = []
    for a in actions:
        items.append(f"""
          <div class="rounded border p-2">
            <span class="inline-block text-[11px] uppercase tracking-wide px-2 py-0.5 rounded bg-slate-900 text-white">{a.get('tool','-')}</span>
            <span class="text-xs text-slate-500 ml-2">args:</span>
            <pre class="mt-1 text-xs bg-slate-50 border rounded p-2 overflow-auto">{_pre(a.get('args',{}))}</pre>
          </div>
        """)
    html = f"""
      <div class="rounded-lg border bg-white">
        <div class="px-4 py-3 border-b">
          <div class="text-xs uppercase tracking-wide text-slate-500">AI PLAN</div>
          <div class="text-slate-800 font-semibold">Scope: <code>{scope}</code></div>
        </div>
        <div class="p-4 space-y-3">
          <div class="text-xs uppercase tracking-wide text-slate-500">Actions</div>
          <div class="space-y-2">{''.join(items)}</div>
          <details class="mt-3">
            <summary class="cursor-pointer text-sm text-slate-700">Raw plan JSON</summary>
            <pre class="mt-2 text-xs bg-slate-50 border rounded p-2 overflow-auto">{_pre(plan)}</pre>
          </details>
        </div>
      </div>
    """
    return HTMLResponse(html)

# Run plan
@router.post("/{scope}/ai/command_run", response_class=HTMLResponse)
async def ai_command_run(request: Request, scope: str):
    settings = get_settings(request)
    outputs_root = Path(settings.OUTPUTS_DIR)

    plan = _get_plan(outputs_root, scope)
    if not plan or not plan.get("actions"):
        return HTMLResponse("<div class='text-sm text-rose-600'>No plan to run. Parse a prompt first.</div>", status_code=400)

    actions: List[Dict[str, Any]] = plan.get("actions", [])
    sections: List[str] = []

    for a in actions:
        tool = (a.get("tool") or "").strip().lower()
        if tool == "list_active_subdomains":
            hosts = _list_active_subdomains(outputs_root, scope)
            li = "".join(
                f"<li><a class='text-blue-700 underline' href='https://{h}' target='_blank' rel='noopener'>{h}</a></li>"
                for h in hosts
            ) or "<li class='text-slate-500'>No subdomains found.</li>"
            sections.append(f"""
              <div class="rounded border p-3 mb-3">
                <div class="text-sm font-semibold text-slate-800">
                  Active subdomains <span class="text-slate-500">({len(hosts)})</span>
                </div>
                <ul class="list-disc ml-5 text-sm mt-2">{li}</ul>
              </div>
            """)

        elif tool == "dirsearch":
            args = a.get("args") or {}
            wl   = args.get("wordlist", "medium")
            host = args.get("host", "__all__")
            sections.append(f"""
              <div class="rounded border p-3 mb-3">
                <div class="text-sm font-semibold text-slate-800">Dirsearch (queued)</div>
                <div class="text-sm text-slate-600">wordlist: <code>{wl}</code> · host: <code>{host}</code></div>
              </div>
            """)
            # TODO: spawn proses dirsearch beneran jika diinginkan

        elif tool == "analyze_urls":
            limit = (a.get("args") or {}).get("limit", 200)
            sections.append(f"""
              <div class="rounded border p-3 mb-3">
                <div class="text-sm font-semibold text-slate-800">Analyze URLs (preview)</div>
                <div class="text-sm text-slate-600">limit: <code>{limit}</code></div>
              </div>
            """)

        else:
            sections.append(f"""
              <div class="rounded border p-3 mb-3">
                <div class="text-sm font-semibold text-slate-800">Unknown tool</div>
                <div class="text-sm"><code>{tool or '-'}</code></div>
              </div>
            """)

    html = f"""
      <div class="space-y-2">
        <div class="text-sm text-emerald-700">Plan executed.</div>
        {''.join(sections)}
      </div>
    """
    return HTMLResponse(html)

# Status/logs (dummy sederhana supaya UI nggak error)
@router.get("/{scope}/ai/job_status", response_class=JSONResponse)
async def ai_job_status(request: Request, scope: str):
    return JSONResponse({
        "status": "ok",
        "logs": [],
        "actions": [],  # kamu bisa isi kalau nanti ada eksekusi asinkron
    })
