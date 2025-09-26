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
    T = get_templates(request)
    st = _store(request, scope)
    threads = st.list_threads()
    curr = thread or (threads[0].id if threads else None)
    msgs = st.read_msgs(curr, limit=300) if curr else []
    ctx = {"request": request, "scope": scope, "threads": threads, "thread_id": curr, "messages": msgs}
    return T.TemplateResponse("ai_command.html", ctx)

@router.get("/{scope}/ai/command/thread_list", response_class=HTMLResponse)
async def ai_command_thread_list(request: Request, scope: str):
    T = get_templates(request)
    st = _store(request, scope)
    threads = st.list_threads()
    return T.TemplateResponse("_ai_cmd_threads.html", {"request": request, "scope": scope, "threads": threads})

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
    return T.TemplateResponse("_ai_cmd_messages.html", {"request": request, "messages": msgs, "thread_id": thread_id})

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

def _confirmation_card(scope: str, thread_id: str) -> str:
    """HTML kecil untuk konfirmasi run/discard."""
    return (
        "<div class='rounded border p-3 bg-amber-50 text-slate-800'>"
        "<div class='font-medium mb-2'>Rencana aksi siap. Jalankan sekarang?</div>"
        f"<div class='flex gap-2'>"
        f"<form hx-post='/targets/{scope}/ai/command/thread/{thread_id}/run' "
        "      hx-target='#ai-conversation' hx-swap='innerHTML' class='inline'>"
        "  <button class='px-3 py-1.5 rounded bg-emerald-600 text-white text-sm hover:bg-emerald-700'>Run</button>"
        "</form>"
        f"<form hx-post='/targets/{scope}/ai/command/thread/{thread_id}/discard' "
        "      hx-target='#ai-conversation' hx-swap='innerHTML' class='inline'>"
        "  <button class='px-3 py-1.5 rounded bg-slate-200 text-slate-800 text-sm hover:bg-slate-300'>Discard</button>"
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
        prompt=base_prompt or user_text, scope=scope, model=model, intent=intent
    )

    # Jika type=actions -> simpan plan, minta konfirmasi
    if parsed.get("type") == "actions":
        plan = parsed.get("plan") or {}
        st.save_plan(thread_id, plan)
        # Catat pesan ringkas + kartu konfirmasi
        st.append_msg(thread_id, Msg.new("assistant", "✔ Plan created.", {}))
        st.append_msg(thread_id, Msg.new("assistant", _confirmation_card(scope, thread_id), {"html": True}))
    else:
        # Chat biasa
        reply = parsed.get("message") or "Baik."
        st.append_msg(thread_id, Msg.new("assistant", reply, {}))

    msgs = st.read_msgs(thread_id)
    return T.TemplateResponse("_ai_cmd_messages.html", {"request": request, "messages": msgs, "thread_id": thread_id})

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
            ok = a.get("result", {}).get("ok")
            items.append(f"{'✅' if ok else '❌'} <code>{tool}</code>")
        html = (
            "<div class='text-sm'>Plan executed.</div>"
            "<ul class='list-disc ml-5 text-sm'>" + "".join(f"<li>{x}</li>" for x in items) + "</ul>"
        )
        st.append_msg(thread_id, Msg.new("assistant", html, {"html": True}))
    except Exception:
        st.append_msg(thread_id, Msg.new("assistant", f"❌ Error running plan:\n```\n{traceback.format_exc()}\n```"))

    msgs = st.read_msgs(thread_id)
    return T.TemplateResponse("_ai_cmd_messages.html", {"request": request, "messages": msgs, "thread_id": thread_id})

@router.post("/{scope}/ai/command/thread/{thread_id}/discard", response_class=HTMLResponse)
async def ai_command_discard(request: Request, scope: str, thread_id: str):
    T = get_templates(request)
    st = _store(request, scope)
    # kosongkan plan (loader akan menganggap 'no plan')
    st.save_plan(thread_id, {})
    st.append_msg(thread_id, Msg.new("assistant", "🗑️ Plan dibatalkan.", {}))
    msgs = st.read_msgs(thread_id)
    return T.TemplateResponse("_ai_cmd_messages.html", {"request": request, "messages": msgs, "thread_id": thread_id})
