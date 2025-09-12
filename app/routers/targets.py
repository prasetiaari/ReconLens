from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse

from app.deps import get_settings, get_templates
from app.services.targets import load_summary, build_module_stats
from app.services.targets import build_target_dashboard as build_dashboard_summary

from time import perf_counter
from datetime import datetime
from pathlib import Path
from shutil import which
from urllib.parse import urlparse, urlunparse
import asyncio
import uuid
import shlex
import sys, os
from typing import Dict, Any

router = APIRouter(prefix="/targets")

# ============================================================
# Job State (in-memory)
# ============================================================
JOBS: Dict[str, Dict[str, Any]] = {}

# ============================================================
# Helpers
# ============================================================

def _nowstamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d-%H%M%S")

def _canon(u: str) -> str:
    try:
        p = urlparse(u.strip())
        scheme = (p.scheme or "http").lower()
        netloc = (p.netloc or "").lower()
        if ":" in netloc:
            host, port = netloc.split(":", 1)
            if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                netloc = host
        return urlunparse(p._replace(scheme=scheme, netloc=netloc, fragment=""))
    except Exception:
        return u.strip()

def _merge_urls(target: Path, newfile: Path):
    """Dedup + merge ke target (urls.txt)."""
    seen: set[str] = set()
    lines: list[str] = []

    def add_file(p: Path):
        if not p.exists():
            return
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                u = ln.strip()
                if not u:
                    continue
                cu = _canon(u)
                if cu in seen:
                    continue
                seen.add(cu)
                lines.append(cu)

    add_file(target)
    add_file(newfile)

    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as out:
        out.write("\n".join(lines) + ("\n" if lines else ""))

def _tool_cmd(tool: str, scope: str, outputs_base: Path) -> list[str]:
    """
    Bangun command untuk tool:
      - gau / waymore : koleksi URL
      - build        : python -m ReconLens (rebuild modul dari urls.txt)
    """
    if tool == "gau":
        if which("gau") is None:
            raise FileNotFoundError("Binary 'gau' not found in PATH")
        # Verbose, biar log ringkas & progres terlihat
        return ["gau", "--verbose", scope]

    if tool == "waymore":
        if which("waymore") is None:
            raise FileNotFoundError("Binary 'waymore' not found in PATH")
        # Output ke stdout agar kita bisa capture line demi line
        return ["waymore", "-i", scope, "-o", "-"]

    if tool == "build":
        # Gunakan interpreter aktif (venv/docker) + modul ReconLens
        out_dir = outputs_base / scope
        urls_txt = out_dir / "urls.txt"
        # Biarkan ReconLens yang menulis file modulnya
        return [
            sys.executable, "-m", "ReconLens",
            "--scope", scope,
            "--input", str(urls_txt),
            "--out", str(out_dir),
        ]

    raise ValueError("unknown tool")

# ============================================================
# Worker
# ============================================================

async def _run_job(scope: str, tool: str, out_dir: Path, job_id: str):
    job = JOBS[job_id]

    # --- prepare dirs --------------------------------------------------------
    out_dir.mkdir(parents=True, exist_ok=True)         # .../ReconLens/outputs/<scope>
    jobs_dir = out_dir / "__jobs__"
    jobs_dir.mkdir(parents=True, exist_ok=True)
    raw_dir  = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    log_path = jobs_dir / f"{job_id}.log"
    tmp_urls = jobs_dir / f"{job_id}.urls"
    raw_path = raw_dir / f"{tool}-{_nowstamp()}.urls"

    job.update({
        "log_path": str(log_path),
        "urls_path": str(tmp_urls),
        "raw_path": str(raw_path),
    })

    log_f      = open(log_path, "w", encoding="utf-8", errors="ignore")
    urls_tmp_f = open(tmp_urls, "w", encoding="utf-8", errors="ignore")
    raw_f      = open(raw_path, "w", encoding="utf-8", errors="ignore")

    captured = 0

    try:
        # Path anatomy:
        # out_dir = .../url_parser_real_world/ReconLens/outputs/<scope>
        outputs_root = out_dir.parent                    # .../url_parser_real_world/ReconLens/outputs
        package_root = outputs_root.parent               # .../url_parser_real_world/ReconLens
        repo_root    = package_root.parent               # .../url_parser_real_world   <-- ini yg harus di-PYTHONPATH & cwd

        cmd = _tool_cmd(tool, scope, outputs_root)       # pastikan "build" mengembalikan: [sys.executable, "-m", "ReconLens", ... ]

        # Pastikan paket ReconLens bisa di-import oleh 'python -m ReconLens'
        env = os.environ.copy()
        env["PYTHONPATH"] = (
            str(repo_root)
            + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(repo_root),           # run dari repo root, bukan dari folder ReconLens/
            env=env,                      # tambahkan repo root ke PYTHONPATH
        )
        job["proc"] = proc
        q: asyncio.Queue[str] = job["queue"]

        await q.put(f"$ {' '.join(shlex.quote(c) for c in cmd)}\n")
        await q.put(f"[info] cwd={repo_root}\n")
        await q.put(f"[info] PYTHONPATH={env['PYTHONPATH']}\n")
        await q.put(f"[info] raw → {raw_path}\n")

        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.decode("utf-8", "ignore").rstrip("\n")

            # write to log
            log_f.write(line + "\n"); log_f.flush()

            # capture URL-ish lines for collectors
            if "://" in line:
                urls_tmp_f.write(line + "\n"); urls_tmp_f.flush()
                raw_f.write(line + "\n");  raw_f.flush()
                captured += 1

            await q.put(line + "\n")

        rc = await proc.wait()
        await q.put(f"\n[exit] code={rc}\n")
        job["exit_code"] = rc

        # close tmp holders before post-processing
        urls_tmp_f.close()
        raw_f.close()

        if tool in ("gau", "waymore"):
            # merge unique URLs into outputs/<scope>/urls.txt
            target = out_dir / "urls.txt"

            def _count_lines(p: Path) -> int:
                try:
                    with p.open("r", encoding="utf-8", errors="ignore") as f:
                        return sum(1 for _ in f)
                except Exception:
                    return 0

            before = _count_lines(target)
            _merge_urls(target, tmp_urls)
            after  = _count_lines(target)
            added_unique = max(0, after - before)

            await q.put(
                f"[summary] captured={captured}  "
                f"unique_added={added_unique}  total_now={after}\n"
            )
            await q.put(f"[summary] merged → {target}\n")
        else:
            # build: engine ReconLens yang menulis file modul
            await q.put(f"[summary] rebuild done. outputs → {out_dir}\n")

    except Exception as e:
        await job["queue"].put(f"[error] {e}\n")
        job["exit_code"] = -1
    finally:
        try:
            log_f.close()
            if not urls_tmp_f.closed:
                urls_tmp_f.close()
            if not raw_f.closed:
                raw_f.close()
        except:
            pass
        await job["queue"].put("[[DONE]]")
        job["done"] = True

# ============================================================
# Pages
# ============================================================

@router.get("/{scope}", response_class=HTMLResponse)
def target_detail(scope: str, request: Request):
    t0 = perf_counter()
    settings = get_settings(request)
    templates = get_templates(request)

    summary = load_summary(settings.OUTPUTS_DIR, scope)
    t1 = perf_counter()
    stats = build_module_stats(settings.OUTPUTS_DIR, scope, settings.MODULES)
    t2 = perf_counter()
    dash = build_dashboard_summary(settings.OUTPUTS_DIR, scope)

    urls_path = settings.OUTPUTS_DIR / scope / "urls.txt"
    try:
        with urls_path.open("r", encoding="utf-8", errors="ignore") as f:
            urls_count = sum(1 for _ in f)
    except FileNotFoundError:
        urls_count = 0
    except Exception:
        urls_count = 0

    env = templates.env
    has_timeago = "timeago" in env.filters
    has_humansize = "humansize" in env.filters

    resp = templates.TemplateResponse("target_detail.html", {
        "request": request,
        "scope": scope,
        "summary": summary,
        "stats": stats,
        "dash": dash,
        "has_timeago": has_timeago,
        "has_humansize": has_humansize,
        "urls_count": urls_count,
    })
    t3 = perf_counter()

    print(
        f"[perf] /targets/{scope} total={(t3-t0)*1000:.1f}ms "
        f"summary={(t1-t0)*1000:.1f}ms build_stats={(t2-t1)*1000:.1f}ms "
        f"render={(t3-t2)*1000:.1f}ms",
        flush=True,
    )
    return resp

@router.get("/{scope}/collect/{tool}", response_class=HTMLResponse)
def collect_console(scope: str, tool: str, request: Request):
    # sekarang support 'build' juga
    if tool not in ("gau", "waymore", "build"):
        return HTMLResponse("Unknown tool", status_code=404)

    settings = get_settings(request)
    templates = get_templates(request)

    out_dir = settings.OUTPUTS_DIR / scope
    urls_txt = out_dir / "urls.txt"

    # Tampilkan halaman runner bersama (collect_console.html)
    return templates.TemplateResponse("collect_console.html", {
        "request": request,
        "scope": scope,
        "tool": tool,                 # 'gau' | 'waymore' | 'build'
        "urls_txt": str(urls_txt),    # info path target
    })

# ============================================================
# Job endpoints (start / stream / cancel)
# ============================================================

@router.post("/{scope}/collect/{tool}/start")
async def collect_start(scope: str, tool: str, request: Request):
    if tool not in ("gau", "waymore", "build"):
        raise HTTPException(404, "unknown tool")

    settings = get_settings(request)
    out_dir = settings.OUTPUTS_DIR / scope

    # Hindari job duplikat untuk scope+tool yang sama
    for jid, j in JOBS.items():
        if not j.get("done") and j["scope"] == scope and j["tool"] == tool:
            return {"job_id": jid, "status": "running"}

    job_id = uuid.uuid4().hex
    q: asyncio.Queue[str] = asyncio.Queue()
    JOBS[job_id] = {
        "scope": scope,
        "tool": tool,
        "queue": q,
        "done": False,
        "exit_code": None,
    }

    asyncio.create_task(_run_job(scope, tool, out_dir, job_id))
    return {"job_id": job_id, "status": "started"}

@router.get("/{scope}/collect/{tool}/stream")
async def collect_stream(scope: str, tool: str, job: str, request: Request):
    meta = JOBS.get(job)
    if not meta or meta.get("scope") != scope or meta.get("tool") != tool:
        raise HTTPException(404, "job not found")

    q: asyncio.Queue[str] = meta["queue"]

    async def gen():
        while True:
            try:
                line = await asyncio.wait_for(q.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # SSE ping
                yield b": keep-alive\n\n"
                continue
            if line == "[[DONE]]":
                yield b"data: [[DONE]]\n\n"
                break
            payload = line.replace("\r", "")
            yield f"data: {payload}\n\n".encode("utf-8")

    return StreamingResponse(gen(), media_type="text/event-stream")

@router.post("/{scope}/collect/{tool}/cancel")
async def collect_cancel(scope: str, tool: str, job: str):
    meta = JOBS.get(job)
    if not meta:
        raise HTTPException(404, "job not found")
    proc = meta.get("proc")
    if proc and proc.returncode is None:
        try:
            proc.terminate()
            meta["done"] = True
            return {"ok": True}
        except ProcessLookupError:
            pass
    return {"ok": False}
