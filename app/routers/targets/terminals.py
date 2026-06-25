from __future__ import annotations
import asyncio
import fcntl
import json
import os
import pty
import select
import shlex
import struct
import subprocess
import termios
import time
from pathlib import Path
from typing import Dict, Any, Optional
from fastapi import APIRouter, Request, HTTPException, Form, WebSocket, WebSocketDisconnect
from app.deps import get_settings
from app.core.pathutils import systemish_path

router = APIRouter()

# In-memory PTY sessions per scope/terminal
# { scope: { term_id: { id, name, master_fd, proc, scrollback } } }
SESSIONS: Dict[str, Dict[str, Any]] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def set_winsize(fd: int, rows: int, cols: int) -> None:
    """Push a TIOCSWINSZ ioctl to resize the PTY window."""
    try:
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
    except Exception:
        pass


def _session_file(outputs_dir: Path, scope: str) -> Path:
    p = outputs_dir / scope / "__cache"
    p.mkdir(parents=True, exist_ok=True)
    return p / "xterm_sessions.json"


def _load_scope(outputs_dir: Path, scope: str) -> None:
    """Load saved tab metadata into SESSIONS (run-time PTY fields start as None)."""
    if scope in SESSIONS:
        return
    path = _session_file(outputs_dir, scope)
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            SESSIONS[scope] = {
                k: {**v, "master_fd": None, "proc": None, "scrollback": b""}
                for k, v in data.items()
            }
        except Exception:
            SESSIONS[scope] = {}
    else:
        SESSIONS[scope] = {}
    # Always guarantee at least one terminal tab
    if not SESSIONS[scope]:
        term_id = f"term_{int(time.time() * 1000)}"
        SESSIONS[scope][term_id] = {
            "id": term_id, "name": "Terminal 1",
            "master_fd": None, "proc": None, "scrollback": b"",
        }


def _save_scope(outputs_dir: Path, scope: str) -> None:
    if scope not in SESSIONS:
        return
    path = _session_file(outputs_dir, scope)
    serializable = {
        k: {"id": v["id"], "name": v["name"]}
        for k, v in SESSIONS[scope].items()
    }
    try:
        path.write_text(json.dumps(serializable, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _spawn_pty(term: Dict[str, Any], cwd: Path, rows: int = 24, cols: int = 200) -> None:
    """Open a PTY pair and launch bash inside it (idempotent — skip if already alive)."""
    proc = term.get("proc")
    if proc and proc.poll() is None:
        return  # bash still running — reuse existing PTY

    master_fd, slave_fd = pty.openpty()
    set_winsize(master_fd, rows, cols)

    env = os.environ.copy()
    env.update({
        "TERM": "xterm-256color",
        "COLORTERM": "truecolor",
        "PATH": systemish_path(),
        "HOME": str(cwd),
        "HISTFILE": str(cwd / ".bash_history"),
    })

    proc = subprocess.Popen(
        ["/bin/bash", "--login"],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        preexec_fn=os.setsid,
        cwd=str(cwd),
        env=env,
    )
    os.close(slave_fd)  # parent only needs master end

    term["master_fd"] = master_fd
    term["proc"] = proc
    term["scrollback"] = b""


def _safe_read(fd: int, size: int = 8192) -> Optional[bytes]:
    """Non-blocking PTY read with 1-second timeout. Returns None on closed fd."""
    try:
        r, _, _ = select.select([fd], [], [], 1.0)
        if r:
            return os.read(fd, size)
        return b""  # timeout — no data yet
    except OSError:
        return None  # PTY closed or process died


# ── HTTP Endpoints (tab management) ──────────────────────────────────────────

@router.get("/{scope}/terminals")
async def list_terminals(scope: str, request: Request):
    settings = get_settings(request)
    outputs_root = Path(settings.OUTPUTS_DIR)
    _load_scope(outputs_root, scope)
    result = []
    for v in SESSIONS[scope].values():
        proc = v.get("proc")
        result.append({
            "id": v["id"],
            "name": v["name"],
            "alive": bool(proc and proc.poll() is None),
        })
    return sorted(result, key=lambda x: x["id"])


@router.post("/{scope}/terminals/create")
async def create_terminal(scope: str, request: Request):
    settings = get_settings(request)
    outputs_root = Path(settings.OUTPUTS_DIR)
    _load_scope(outputs_root, scope)
    count = len(SESSIONS[scope]) + 1
    term_id = f"term_{int(time.time() * 1000)}"
    SESSIONS[scope][term_id] = {
        "id": term_id,
        "name": f"Terminal {count}",
        "master_fd": None,
        "proc": None,
        "scrollback": b"",
    }
    _save_scope(outputs_root, scope)
    return {"ok": True, "id": term_id}


@router.post("/{scope}/terminals/{term_id}/close")
async def close_terminal(scope: str, term_id: str, request: Request):
    settings = get_settings(request)
    outputs_root = Path(settings.OUTPUTS_DIR)
    _load_scope(outputs_root, scope)
    if term_id not in SESSIONS[scope]:
        raise HTTPException(status_code=404, detail="Terminal not found")
    term = SESSIONS[scope][term_id]
    if term.get("proc"):
        try:
            term["proc"].kill()
        except Exception:
            pass
    if term.get("master_fd") is not None:
        try:
            os.close(term["master_fd"])
        except Exception:
            pass
    del SESSIONS[scope][term_id]
    if not SESSIONS[scope]:
        new_id = f"term_{int(time.time() * 1000)}"
        SESSIONS[scope][new_id] = {
            "id": new_id, "name": "Terminal 1",
            "master_fd": None, "proc": None, "scrollback": b"",
        }
    _save_scope(outputs_root, scope)
    return {"ok": True}


# ── WebSocket PTY Bridge ──────────────────────────────────────────────────────

@router.websocket("/{scope}/terminals/{term_id}/ws")
async def terminal_ws(websocket: WebSocket, scope: str, term_id: str):
    """
    Bidirectional WebSocket ↔ PTY bridge.
    - Browser input  → PTY stdin  (keystrokes, special keys)
    - PTY output     → Browser    (raw bytes including ANSI codes)
    - JSON resize msg→ TIOCSWINSZ ioctl
    """
    await websocket.accept()

    try:
        settings = get_settings(websocket)
    except Exception:
        await websocket.close(code=4000)
        return

    outputs_root = Path(settings.OUTPUTS_DIR)
    cwd = outputs_root / scope
    cwd.mkdir(parents=True, exist_ok=True)
    _load_scope(outputs_root, scope)

    if term_id not in SESSIONS[scope]:
        await websocket.close(code=4004)
        return

    term = SESSIONS[scope][term_id]
    _spawn_pty(term, cwd)
    master_fd = term["master_fd"]

    # Replay scrollback so reconnecting clients see prior output
    if term["scrollback"]:
        try:
            await websocket.send_bytes(term["scrollback"])
        except Exception:
            pass

    loop = asyncio.get_event_loop()

    async def pty_to_ws():
        """Stream PTY output → WebSocket."""
        while True:
            try:
                data = await loop.run_in_executor(None, _safe_read, master_fd)
                if data is None:
                    break  # PTY closed
                if data:
                    term["scrollback"] = (term["scrollback"] + data)[-100_000:]
                    await websocket.send_bytes(data)
            except Exception:
                break

    async def ws_to_pty():
        """Stream WebSocket input → PTY stdin."""
        while True:
            try:
                msg = await websocket.receive()
                if msg["type"] == "websocket.disconnect":
                    break

                raw = msg.get("bytes") or (msg.get("text") or "").encode()
                if not raw:
                    continue

                # Attempt JSON parse for control messages (e.g. resize)
                is_resize = False
                try:
                    ctrl = json.loads(raw)
                    if isinstance(ctrl, dict) and ctrl.get("type") == "resize":
                        set_winsize(
                            master_fd,
                            int(ctrl.get("rows", 24)),
                            int(ctrl.get("cols", 80)),
                        )
                        is_resize = True
                except Exception:
                    pass

                if is_resize:
                    continue

                # Regular input: write raw bytes to PTY master
                os.write(master_fd, raw if isinstance(raw, bytes) else raw.encode())
            except Exception:
                break

    pty_task = asyncio.create_task(pty_to_ws())
    ws_task = asyncio.create_task(ws_to_pty())
    await asyncio.wait([pty_task, ws_task], return_when=asyncio.FIRST_COMPLETED)
    pty_task.cancel()
    ws_task.cancel()
