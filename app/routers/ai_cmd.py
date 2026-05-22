# app/routers/ai_cmd.py
from __future__ import annotations
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from pathlib import Path
import json, re, traceback
from typing import Optional

from ..deps import get_settings, get_templates
from app.services.ai_cmd_store import AiCmdStore, Msg
# ⬇️ pakai wrapper baru (kita tambah di ai_rulegen.py)
from app.services.ai_rulegen import parse_prompt_to_plan_or_chat
# eksekusi plan tetap sama
from app.services.ai_jobs import run_plan_now  # <- gunakan run_plan_now yang sudah ada

router = APIRouter(prefix="/targets", tags=["ai-command"])

def _store(request: Request, scope: str) -> AiCmdStore:
    outputs_root = Path(get_settings(request).OUTPUTS_DIR)
    return AiCmdStore(outputs_root, scope)

# ---------- UI ----------
@router.get("/{scope}/ai/command", response_class=HTMLResponse)
async def ai_command_home(request: Request, scope: str, thread: Optional[str] = None):
    from app.core.config_store import load_settings
    from fastapi.responses import RedirectResponse
    if (load_settings() or {}).get("ai", {}).get("disable", False):
        return RedirectResponse(url=f"/targets/{scope}")

    T = get_templates(request)
    st = _store(request, scope)
    threads = st.list_threads()
    curr = thread or (threads[0].id if threads else None)
    msgs = st.read_msgs(curr, limit=300) if curr else []
    ctx = {"request": request, "scope": scope, "threads": threads, "thread_id": curr, "messages": msgs}
    return T.TemplateResponse("ai/command.html", ctx)

@router.get("/{scope}/ai/command/thread_list", response_class=HTMLResponse)
async def ai_command_thread_list(request: Request, scope: str):
    T = get_templates(request)
    st = _store(request, scope)
    threads = st.list_threads()
    curr = request.query_params.get("thread")
    return T.TemplateResponse("ai/partials/_ai_cmd_threads.html", {"request": request, "scope": scope, "threads": threads, "thread_id": curr})

@router.post("/{scope}/ai/command/thread", response_class=JSONResponse)
async def ai_command_new_thread(request: Request, scope: str, title: str = Form(...)):
    st = _store(request, scope)
    info = st.create_thread(title)
    # biar frontend bisa redirect ke ?thread=<id>
    return JSONResponse({"ok": True, "thread_id": info.id, "title": info.title})

@router.get("/{scope}/ai/command/thread/{thread_id}", response_class=HTMLResponse)
async def ai_command_load_thread(request: Request, scope: str, thread_id: str):
    T = get_templates(request)
    st = _store(request, scope)
    msgs = st.read_msgs(thread_id, limit=300)
    return T.TemplateResponse("ai/partials/_ai_cmd_messages.html", {"request": request, "messages": msgs, "thread_id": thread_id})

# ---------- Helpers untuk konfirmasi ----------
YES_PAT = re.compile(r"^\s*(ya|y|yes|ok|oke|yap|yup|sip|gas|lanjut|silakan|jalankan|jalan(?:kan)?)\s*[.!]*\s*$", re.I)
MAKE_PLAN_PAT = re.compile(r"(buat(?:kan)?\s*rencana(?:\s*aksi)?|create\s*plan|rencana\s*aksi)", re.I)

def _last_meaningful_user(st: AiCmdStore, thread_id: str) -> Optional[str]:
    """Cari pesan user terakhir yang 'bermakna' (bukan 'ya/ok')."""
    msgs = st.read_msgs(thread_id, limit=200)
    for m in reversed(msgs):
        if m.role == "user":
            txt = (m.text or "").strip()
            if not YES_PAT.match(txt) and len(txt) >= 3:
                return txt
    return None

def _confirmation_card(scope: str, thread_id: str, plan: Dict[str, Any]) -> str:
    """HTML kecil untuk konfirmasi run/discard dengan list tindakan."""
    actions = plan.get("actions") or []
    items = []
    for a in actions:
        tool = a.get("tool") or ""
        args = a.get("args") or {}
        # Format argumen secara ringkas
        args_str = ", ".join(f"{k}={v}" for k, v in args.items() if k != "target")
        args_lbl = f" ({args_str})" if args_str else ""
        items.append(f"<li><code>{tool}</code>{args_lbl}</li>")

    list_html = ""
    if items:
        list_html = (
            "<div class='text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1 mt-1'>Tindakan yang akan dijalankan:</div>"
            "<ul class='list-disc pl-5 text-sm space-y-1 mb-3 text-slate-700'>" + "".join(items) + "</ul>"
        )

    return (
        "<div class='rounded border p-3 bg-amber-50 text-slate-800 border-amber-200 shadow-sm'>"
        "<div class='font-medium mb-2 text-amber-900'>Rencana aksi siap. Jalankan sekarang?</div>"
        f"{list_html}"
        f"<div class='flex gap-2'>"
        f"<form hx-post='/targets/{scope}/ai/command/thread/{thread_id}/run' "
        "      hx-target='#ai-conversation' hx-swap='innerHTML' class='inline'>"
        "  <button class='px-3 py-1.5 rounded bg-emerald-600 text-white text-sm hover:bg-emerald-700 font-medium transition shadow-sm'>Run</button>"
        "</form>"
        f"<form hx-post='/targets/{scope}/ai/command/thread/{thread_id}/discard' "
        "      hx-target='#ai-conversation' hx-swap='innerHTML' class='inline'>"
        "  <button class='px-3 py-1.5 rounded bg-slate-200 text-slate-800 text-sm hover:bg-slate-300 font-medium transition shadow-sm'>Discard</button>"
        "</form>"
        "</div></div>"
    )

# ---------- Parse prompt -> chat / plan (dengan konfirmasi) ----------
@router.post("/{scope}/ai/command/thread/{thread_id}/parse", response_class=HTMLResponse)
async def ai_command_parse(
    request: Request,
    scope: str,
    thread_id: str,
    prompt: str = Form(...),
    model: str = Form("llama3.2:3b"),
    intent: str = Form("auto"),
):
    T = get_templates(request)
    st = _store(request, scope)
    history_msgs = st.read_msgs(thread_id)

    user_text = (prompt or "").strip()
    st.append_msg(thread_id, Msg.new("user", user_text, {"model": model, "intent": intent}))

    # Deteksi affirmations / perintah 'buatkan rencana'
    base_prompt: Optional[str] = None
    if YES_PAT.match(user_text) or MAKE_PLAN_PAT.search(user_text):
        base_prompt = _last_meaningful_user(st, thread_id)
        # fallback kalau belum ada konteks
        if not base_prompt:
            base_prompt = user_text

    # Panggil wrapper parser
    parsed = parse_prompt_to_plan_or_chat(
        prompt=base_prompt or user_text, scope=scope, model=model, intent=intent,
        history=history_msgs
    )

    # Jika type=actions -> simpan plan, minta konfirmasi
    if parsed.get("type") == "actions":
        plan = parsed.get("plan") or {}
        st.save_plan(thread_id, plan)
        # Catat pesan ringkas + kartu konfirmasi
        st.append_msg(thread_id, Msg.new("assistant", "✔ Plan created.", {}))
        st.append_msg(thread_id, Msg.new("assistant", _confirmation_card(scope, thread_id, plan), {"html": True}))
    else:
        # Chat biasa
        reply = parsed.get("reply") or parsed.get("message") or "Baik."
        meta = parsed.get("meta") or {}
        st.append_msg(thread_id, Msg.new("assistant", reply, meta))

    msgs = st.read_msgs(thread_id)
    return T.TemplateResponse("ai/partials/_ai_cmd_messages.html", {"request": request, "messages": msgs, "thread_id": thread_id})

# ---------- Run / Discard ----------
@router.post("/{scope}/ai/command/thread/{thread_id}/run", response_class=HTMLResponse)
async def ai_command_run(request: Request, scope: str, thread_id: str):
    T = get_templates(request)
    st = _store(request, scope)
    plan = st.load_plan(thread_id)
    if not plan:
        return HTMLResponse("<div class='text-sm text-rose-600'>No plan to run. Create a plan first.</div>")

    try:
        state = run_plan_now(outputs_root=Path(get_settings(request).OUTPUTS_DIR), scope=scope, plan=plan)
        # Render hasil ringkas
        items = []
        for a in state.get("actions", []):
            tool = a.get("tool")
            res = a.get("result") or {}
            ok = res.get("ok")
            detail = ""
            if not ok:
                err_msg = res.get("error") or "Gagal menjalankan tugas."
                detail = f" — <span class='text-rose-500 text-xs'>{err_msg}</span>"
            else:
                # Untuk tool apa pun yang sukses, jika ada summary/message, tampilkan secara premium!
                summ = res.get("summary") or {}
                status = summ.get("status") or ""
                msg = summ.get("message") or ""
                if status or msg:
                    detail = f"<br/><span class='text-slate-700 text-xs font-semibold'>{status}</span>{msg}"
                elif "alive" in res:
                    # Fallback subdomains_alive list
                    detail = f"<br/><span class='text-slate-500 text-xs'>Ditemukan {res.get('count', 0)} subdomain aktif.</span>"
            items.append(f"<li>{'✅' if ok else '❌'} <code>{tool}</code>{detail}</li>")
        html = (
            "<div class='text-sm font-medium text-slate-700 mb-1'>Plan executed:</div>"
            "<ul class='list-disc pl-5 text-sm space-y-1'>" + "".join(items) + "</ul>"
        )
        st.append_msg(thread_id, Msg.new("assistant", html, {"html": True}))
    except Exception:
        st.append_msg(thread_id, Msg.new("assistant", f"❌ Error running plan:\n```\n{traceback.format_exc()}\n```"))

    msgs = st.read_msgs(thread_id)
    return T.TemplateResponse("ai/partials/_ai_cmd_messages.html", {"request": request, "messages": msgs, "thread_id": thread_id})

@router.post("/{scope}/ai/command/thread/{thread_id}/discard", response_class=HTMLResponse)
async def ai_command_discard(request: Request, scope: str, thread_id: str):
    T = get_templates(request)
    st = _store(request, scope)
    # kosongkan plan (loader akan menganggap 'no plan')
    st.save_plan(thread_id, {})
    st.append_msg(thread_id, Msg.new("assistant", "🗑️ Plan dibatalkan.", {}))
    msgs = st.read_msgs(thread_id)
    return T.TemplateResponse("ai/partials/_ai_cmd_messages.html", {"request": request, "messages": msgs, "thread_id": thread_id})
