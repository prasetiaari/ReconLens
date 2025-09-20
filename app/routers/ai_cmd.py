# app/routers/ai_cmd.py
from __future__ import annotations

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from pathlib import Path
import json, traceback
from typing import Optional

# gunakan deps helper yang sudah ada di project
from ..deps import get_settings, get_templates

from app.services.ai_cmd_store import AiCmdStore, Msg
from app.services.ai_rulegen import parse_prompt_to_plan
from app.services.ai_jobs import (
    run_plan_now,           # <— fungsi sinkron eksekusi plan
    set_current_plan,
    get_current_plan,
)

router = APIRouter(prefix="/targets", tags=["ai-command"])


def _store(request: Request, scope: str) -> AiCmdStore:
    outputs_root = Path(get_settings(request).OUTPUTS_DIR)
    return AiCmdStore(outputs_root, scope)


# ---------- UI: halaman utama ----------
@router.get("/{scope}/ai/command", response_class=HTMLResponse)
async def ai_command_home(request: Request, scope: str, thread: Optional[str] = None):
    """
    Render halaman AI Command.
    Catatan: sebagian env FastAPI kadang tidak mengisi argumen opsional 'thread'.
    Supaya aman, ambil juga dari query_params.
    """
    T = get_templates(request)
    st = _store(request, scope)

    # fallback ambil dari query jika argumen kosong
    thread_q = thread or request.query_params.get("thread") or None

    threads = st.list_threads()
    curr = thread_q or (threads[0].id if threads else None)
    msgs = st.read_msgs(curr, limit=300) if curr else []

    ctx = {
        "request": request,
        "scope": scope,
        "threads": threads,
        "thread_id": curr,
        "messages": msgs,
    }
    return T.TemplateResponse("ai_command.html", ctx)


# ---------- API: buat thread baru ----------
@router.post("/{scope}/ai/command/thread", response_class=HTMLResponse)
async def ai_command_new_thread(request: Request, scope: str, title: str = Form(...)):
    """
    Buat thread -> arahkan (HX-Redirect) ke halaman dengan ?thread=<id>
    """
    st = _store(request, scope)
    info = st.create_thread(title)
    target = f"/targets/{scope}/ai/command?thread={info.id}"
    # htmx akan mengikuti HX-Redirect walau body kosong
    return HTMLResponse(status_code=204, headers={"HX-Redirect": target})


# ---------- API: load thread (partial messages) ----------
@router.get("/{scope}/ai/command/thread/{thread_id}", response_class=HTMLResponse)
async def ai_command_load_thread(request: Request, scope: str, thread_id: str):
    T = get_templates(request)
    st = _store(request, scope)
    msgs = st.read_msgs(thread_id, limit=300)
    return T.TemplateResponse(
        "_ai_cmd_messages.html",
        {"request": request, "messages": msgs, "thread_id": thread_id},
    )


# === NEW: render daftar thread sebagai fragment ===
@router.get("/{scope}/ai/command/thread_list", response_class=HTMLResponse)
async def ai_command_thread_list(request: Request, scope: str):
    T = get_templates(request)
    st = _store(request, scope)
    threads = st.list_threads()
    return T.TemplateResponse("_ai_cmd_threads.html",
                              {"request": request, "threads": threads, "scope": scope})
                              
# ---------- API: parse prompt -> plan (save ke thread & append msg) ----------
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

    # simpan user message
    st.append_msg(thread_id, Msg.new("user", prompt, {"model": model, "intent": intent}))

    # panggil parser untuk bikin plan
    plan = parse_prompt_to_plan(prompt=prompt, scope=scope, model=model, intent=intent)
    st.save_plan(thread_id, plan)

    # simpan assistant message ringkas
    st.append_msg(thread_id, Msg.new("assistant", "✔ Plan created.", {"kind": "plan"}))

    ctx = {
        "request": request,
        "messages": st.read_msgs(thread_id),
        "thread_id": thread_id,
        # optional kalau mau ditampilkan di panel lain:
        "plan_json": json.dumps(plan, indent=2, ensure_ascii=False),
    }
    return T.TemplateResponse("_ai_cmd_messages.html", ctx)


# ---------- API: run last plan (sinkron, ringkas) ----------
@router.post("/{scope}/ai/command/thread/{thread_id}/run", response_class=HTMLResponse)
async def ai_command_run(request: Request, scope: str, thread_id: str):
    T = get_templates(request)
    st = _store(request, scope)

    # load plan dari storage; fallback dari jobs store bila ada
    plan = st.load_plan(thread_id)
    if not plan:
        # fallback dari lokasi "current plan" (opsional)
        outputs_root = Path(get_settings(request).OUTPUTS_DIR)
        plan = get_current_plan(outputs_root, scope)

    if not plan:
        return HTMLResponse(
            "<div class='text-sm text-rose-600'>No plan to run. Create a plan first.</div>"
        )

    try:
        outputs_root = Path(get_settings(request).OUTPUTS_DIR)
        # catat sebagai current plan (opsional)
        set_current_plan(outputs_root, scope, plan)

        # jalankan plan sinkron dan rangkum hasil jadi HTML sederhana
        state = run_plan_now(outputs_root=outputs_root, scope=scope, plan=plan)

        # bikin HTML ringkas hasilnya
        parts = ["<div class='text-sm text-emerald-700'>Plan executed.</div>"]
        for a in state.get("actions", []):
            tool = a.get("tool", "-")
            ok = bool(a.get("result", {}).get("ok"))
            icon = "✅" if ok else "❌"
            # contoh khusus hasil subdomain
            if tool == "subdomains_alive" and ok:
                alive = a["result"].get("alive", [])
                parts.append("<div class='mt-2 text-sm'>Active subdomains (" + str(len(alive)) + "):</div>")
                parts.append("<ul class='list-disc ml-5 text-sm'>")
                for h in alive[:1000]:
                    url = ("http://" + h) if not h.startswith("http") else h
                    parts.append(f"<li><a class='text-blue-700 underline' href='{url}' target='_blank' rel='noopener'>{h}</a></li>")
                parts.append("</ul>")
            else:
                parts.append(f"<div class='text-sm'>{icon} <code>{tool}</code></div>")

        result_html = "\n".join(parts)

        # simpan ke chat
        st.append_msg(thread_id, Msg.new("assistant", result_html, {"kind": "result", "html": True}))

        ctx = {"request": request, "messages": st.read_msgs(thread_id), "thread_id": thread_id}
        return T.TemplateResponse("_ai_cmd_messages.html", ctx)

    except Exception:
        st.append_msg(thread_id, Msg.new("assistant", f"❌ Error running plan:\n```\n{traceback.format_exc()}\n```"))
        ctx = {"request": request, "messages": st.read_msgs(thread_id), "thread_id": thread_id}
        return T.TemplateResponse("_ai_cmd_messages.html", ctx)
