from __future__ import annotations
import os, asyncio, json, shlex, signal, shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from app.config import Settings
from app.deps import get_settings, get_templates
from ...services.wordlists import resolve_wordlist
from app.core.urlutils import normalize_host, host_in_scope
from app.services.exec_tools import build_tool_cmd
from app.core.pathutils import systemish_path
from app.core.constants import OUTPUTS_DIR
from .parsers import parse_dirsearch_line
from .utils import (
    read_text_lines,
    merge_urls,
    merge_hostnames,
    safe_json_load,
    update_url_enrich_from_dirsearch,
)

from app.core.meta import update_last_scan, update_dirsearch_last

router = APIRouter(tags=["Targets (jobs)"])


# ======================================================================
# In-memory Job Registry
# ======================================================================

JOBS: Dict[str, Dict[str, Any]] = {}
"""
JOBS[job_id] = {
    "queue": asyncio.Queue[str],
    "proc": Process,
    "done": bool,
    "exit_code": int,
    "scope": str,
    "tool": str,
    "module": Optional[str],
    "host": Optional[str],
    "wordlists": Optional[str],
    "log_path": str,
    "urls_path": str,
    "raw_path": str
}
"""


# ======================================================================
# Utilities
# ======================================================================

def _new_job(scope: str, tool: str, module: str | None = None,
             host: str | None = None, wordlists: str | None = None) -> str:
    """Create a new job entry and initialize its async queue."""
    jid = os.urandom(12).hex()
    JOBS[jid] = {
        "queue": asyncio.Queue(),
        "proc": None,
        "done": False,
        "exit_code": None,
        "scope": scope,
        "tool": tool,
        "module": module,
        "host": host,
        "wordlists": wordlists,
    }
    return jid


def _run_build_inproc(outputs_root: Path, scope: str, log):
    """
    Minimal in-process build step that replaces the missing `ReconLens` module.
    Categorizes URLs into basic buckets (admin, api, etc.).
    """
    out_dir = outputs_root / scope
    urls_txt = out_dir / "urls.txt"
    if not urls_txt.exists():
        log("[build] urls.txt not found; nothing to do\n")
        return {"total": 0, "categorized": 0}

    rules = {
        "admin_panel":       ["/admin", "/wp-admin", "/administrator"],
        "auth_login":        ["/login", "/signin", "/account/login"],
        "api":               ["/api/", "/v1/", "/v2/"],
        "upload":            ["/upload", "/uploader"],
        "docs_swagger":      ["/swagger", "/api-doc", "/api-docs", "/openapi"],
        "debug_dev":         ["/debug", "/_debug", "/__debug__"],
        "config_backup_source": [".env", ".git/", ".gitignore", ".svn", ".bak", "~", ".old", ".zip"],
        "file_disclosure":   ["/.git", "/.svn", "/.hg", "/WEB-INF", "/server-status"],
        "static_assets":     ["/static/", "/assets/", "/dist/", "/build/"],
    }

    bucket_files = {n: (out_dir / f"{n}.txt").open("a", encoding="utf-8") for n in rules}
    other_f = (out_dir / "other.txt").open("a", encoding="utf-8")

    total, categorized = 0, 0
    with urls_txt.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            u = line.strip()
            if not u:
                continue
            total += 1
            lower = u.lower()
            matched = False
            for name, needles in rules.items():
                if any(n in lower for n in needles):
                    bucket_files[name].write(u + "\n")
                    matched = True
                    categorized += 1
                    break
            if not matched:
                other_f.write(u + "\n")

    for fp in bucket_files.values():
        fp.close()
    other_f.close()

    update_last_scan(scope, "build", outputs_root)
    return {"total": total, "categorized": categorized}


# ======================================================================
# Job Runner
# ======================================================================

async def _run_job(
    scope: str,
    tool: str,
    out_dir: Path,
    job_id: str,
    *,
    settings: Settings | None = None,
):
    job = JOBS[job_id]
    q: asyncio.Queue[str] = job["queue"]

    # dirs
    out_dir.mkdir(parents=True, exist_ok=True)
    jobs_dir = out_dir / "__jobs__"
    jobs_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    log_path = jobs_dir / f"{job_id}.log"
    tmp_urls = jobs_dir / f"{job_id}.urls"
    raw_path = raw_dir / f"{tool}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.urls"
    job.update({"log_path": str(log_path), "urls_path": str(tmp_urls), "raw_path": str(raw_path)})

    MAX_PREVIEW_LINES = 500
    captured = 0

    try:
        # ---------------------------------------------------------------------------------
        # IMPORTANT: project roots (samakan seperti "old" layout supaya -m ReconLens ketemu)
        # outputs_root      = /.../ReconLens/outputs
        # repo_root         = /.../ReconLens
        # project_root(old) = /.../                      <-- ini yg dipakai sebagai CWD & PYTHONPATH
        # ---------------------------------------------------------------------------------
        outputs_root = out_dir.parent
        repo_root    = outputs_root.parent
        project_root = repo_root.parent

        # --- prepare special outfile for dirsearch (keep outputs inside project) ---
        dirsearch_outfile = None


        if tool == "dirsearch":
            # try resolve host from job registry if not present
            host = (job.get("host") or "").strip().lower()
            if not host and job_id in JOBS:
                host = (JOBS[job_id].get("host") or "").strip().lower()

            # safe internal output location: outputs/<scope>/dirsearch/<host>/<job_id>.txt
            host_dir = out_dir / "dirsearch" / host
            host_dir.mkdir(parents=True, exist_ok=True)
            dirsearch_outfile = host_dir / f"{job_id}.txt"

        # Build command (pastikan build_tool_cmd("build", ...) memang return ['python', '-m', 'ReconLens', ...])
        cmd = build_tool_cmd(
            tool,
            scope,
            outputs_root,
            module=job.get("module"),
            host=job.get("host"),
            wordlists=job.get("wordlists"),
            settings=settings,
            dirsearch_outfile=dirsearch_outfile,
        )

        # Env & CWD sama seperti “old”
        env = os.environ.copy()
        env["PYTHONPATH"] = str(project_root)
        # biar tools eksternal (gau/dirsearch) lebih mudah ditemukan
        env["PATH"] = systemish_path()

        # --- info lines (harus keluar sebelum proses jalan, seperti contoh lama) ---
        await q.put(f"$ {' '.join(shlex.quote(c) for c in cmd)}\n")
        await q.put(f"[info] cwd={project_root}\n")
        await q.put(f"[info] PYTHONPATH={env['PYTHONPATH']}\n")
        await q.put(f"[info] raw → {raw_path}\n")

        # Jalankan proses dari project_root (bukan dari repo_root/ReconLens)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(project_root),
            env=env,
        )
        job["proc"] = proc
        await q.put("event: status\ndata: running\n\n")

        # Stream stdout (akan memunculkan "Classifying: ...", tabel ascii, dll dari CLI)
        assert proc.stdout is not None
        preview_count = 0
        preview_capped = False
        with open(log_path, "w", encoding="utf-8", errors="ignore") as log_f, \
             open(tmp_urls, "w", encoding="utf-8", errors="ignore") as urls_f, \
             open(raw_path, "w", encoding="utf-8", errors="ignore") as raw_f:

            async for raw in proc.stdout:
                line = raw.decode("utf-8", "ignore").rstrip("\n")
                log_f.write(line + "\n"); log_f.flush()
                raw_f.write(line + "\n"); raw_f.flush()

                # Capture heuristics (tetap seperti sebelumnya)
                if tool == "dirsearch":
                    pass
                elif "://" in line or tool in ("subfinder", "amass", "findomain"):
                    if line.strip():
                        urls_f.write(line.strip() + "\n"); urls_f.flush()
                        captured += 1

                if not preview_capped:
                    preview_count += 1
                    if preview_count <= MAX_PREVIEW_LINES:
                        await q.put(line[:200] + "\n")
                    else:
                        preview_capped = True
                        await q.put(f"[info] (preview truncated at {MAX_PREVIEW_LINES} lines to keep the browser responsive)\n")

        rc = await proc.wait()
        job["exit_code"] = rc
        await q.put(f"\n[exit] code={rc}\n")

        # Merge & summaries (sama seperti dulu)
        await _handle_merge(
            tool, scope, out_dir, tmp_urls, captured, q,
            module_name=job.get("module"),
            job_id=job_id,
            host=job.get("host"),
            dirsearch_outfile=dirsearch_outfile,
            outputs_root=outputs_root,
            )

        await q.put("event: status\ndata: done\n\n")

    except Exception as e:
        await q.put(f"[error] {e}\n")
        job["exit_code"] = -1
        await q.put("event: status\ndata: done\n\n")
    finally:
        job["done"] = True
        await q.put("[[DONE]]")


async def _handle_merge(tool: str, scope: str, out_dir: Path, tmp_urls: Path, captured: int,
                        q: asyncio.Queue[str],
                        module_name: str | None = None,
                        job_id: str | None = None,
                        host: str | None = None,
                        outputs_root: Optional[Path] = None,
                        dirsearch_outfile: Optional[Path] = None,
                        ):
    if outputs_root==None: outputs_root = out_dir.parent
    if tool in ("gau", "waymore"):
        target = out_dir / "urls.txt"
        before = read_text_lines(target)
        merge_urls(target, tmp_urls)
        after  = read_text_lines(target)
        added  = max(0, after - before)
        await q.put(f"[summary] captured={captured}  unique_added={added}  total_now={after}\n")

    elif tool in ("subfinder", "amass", "findomain"):
        target = out_dir / "subdomains.txt"
        before = read_text_lines(target)
        merge_hostnames(target, tmp_urls)
        after  = read_text_lines(target)
        added  = max(0, after - before)
        update_last_scan(scope, tool, out_dir.parent)
        await q.put(f"[summary] captured={captured}  unique_added={added}  total_now={after}\n")

    elif tool == "build":
        update_last_scan(scope, "build", out_dir.parent)
        # === samakan wording lama:
        await q.put(f"[summary] rebuild done. outputs → {out_dir}\n")

    elif tool in ("probe_subdomains", "probe_module"):
        key = (module_name or tool).lower()
        if key == "probe_subdomains":
            key = "subdomains"
        update_last_scan(scope, key, out_dir.parent)
        await q.put(f"[summary] probe ({key}) complete\n")

    elif tool == "dirsearch":
        # resolve host
        if not host and job_id:
            host = (JOBS.get(job_id, {}).get("host") or "").strip().lower()
        host = (host or "").strip().lower()
        # Folder host di outputs/<scope>/dirsearch/<host>/
        host_dir = out_dir / "dirsearch" / host
        host_dir.mkdir(parents=True, exist_ok=True)
        # Sumber hasil: pakai file -o jika ada, kalau tidak fallback ke tmp_urls
        src_file = None
        try:
            # dirsearch_outfile diset di _run_job saat build cmd; kalau ada, pakai itu
            if dirsearch_outfile:
                p = Path(dirsearch_outfile)
                if p.exists():
                    src_file = p
        except NameError:
            # variabel tidak ada → fallback ke tmp_urls
            pass
        if src_file is None:
            src_file = Path(tmp_urls)

        # Simpan laporan job (selalu .txt) → konsisten dengan versi lama
        job_report = host_dir / f"{(job_id or 'job')}.txt"
        try:
            # copy isi dari sumber ke job_report (bukan replace tmp_urls lagi)
            if src_file.exists():
                shutil.copy2(src_file, job_report)
            else:
                job_report.touch()
        except Exception:
            # jangan fail keras; tetap lanjut merge
            job_report.touch()
        # 2) merge semua temuan host ini → found.txt
        found = host_dir / "found.txt"
        before_host = read_text_lines(found)
        merge_urls(found, job_report)
        after_host = read_text_lines(found)
        # 3) merge seluruh temuan → outputs/<scope>/dirsearch.txt
        agg = out_dir / "dirsearch.txt"
        before_agg = read_text_lines(agg)
        merge_urls(agg, job_report)
        after_agg = read_text_lines(agg)
        # 4) update penanda waktu
        update_dirsearch_last(outputs_root, scope, host)  # __cache/dirsearch_last.json
        update_last_scan(scope, "dirsearch", outputs_root)
        await q.put(
            f"[summary] captured={captured}  unique_added_host={max(0, after_host - before_host)}  host_total={after_host}\n"
        )
        await q.put(
            f"[summary] merged (aggregate) → {agg}  unique_added_agg={max(0, after_agg - before_agg)}  agg_total={after_agg}\n"
        )

# ======================================================================
# Routes
# ======================================================================

@router.get("/{scope}/collect/{tool}", response_class=HTMLResponse)
async def collect_console(request: Request, scope: str, tool: str, module: Optional[str] = None):
    """Render collection console page for a given tool."""
    templates = get_templates(request)
    out_dir = OUTPUTS_DIR / scope
    meta = safe_json_load(out_dir / "meta.json")
    last_scans = meta.get("last_scans", {})
    wordlist = request.query_params.get("wordlist") or "dicc.txt"
    host = request.query_params.get("host") or ""

    return templates.TemplateResponse("admin/collect_console.html", {
        "request": request,
        "scope": scope,
        "tool": tool,
        "module": module,
        "last_scans": last_scans,
        "host": host,
        "wordlist": wordlist,
    })


@router.post("/{scope}/collect/{tool}/start")
async def collect_start(scope: str, tool: str, request: Request):
    """Start a recon job (gau, waymore, dirsearch, etc.)"""
    module = request.query_params.get("module")
    host = request.query_params.get("host") or ""
    wl_name = request.query_params.get("wordlist") or "dicc.txt"

    if tool == "dirsearch":
        if not host:
            return JSONResponse({"ok": False, "error": "host param required"}, status_code=400)
        wl_path = resolve_wordlist(wl_name)
        if wl_path is None:
            wl_name = "dicc.txt"

        if not host_in_scope(host, scope):
            return JSONResponse({"ok": False, "error": "host not in scope"}, status_code=400)

        jid = _new_job(scope, tool, host=normalize_host(host), wordlists=wl_name)
    else:
        jid = _new_job(scope, tool, module=module, host=host)

    out_dir = OUTPUTS_DIR / scope
    settings = get_settings(request)
    asyncio.create_task(_run_job(scope, tool, out_dir, jid, settings=settings))
    return JSONResponse({"ok": True, "job_id": jid})


@router.post("/{scope}/collect/{tool}/cancel")
async def collect_cancel(scope: str, tool: str, job: str):
    """Cancel a running job by sending SIGINT."""
    info = JOBS.get(job)
    if not info:
        return JSONResponse({"ok": False, "error": "job not found"})

    proc = info.get("proc")
    if proc and proc.returncode is None:
        try:
            proc.send_signal(signal.SIGINT)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass
    return JSONResponse({"ok": True})


@router.get("/{scope}/collect/{tool}/stream")
async def collect_stream(scope: str, tool: str, job: str):
    """Stream job output via Server-Sent Events."""
    info = JOBS.get(job)
    if not info:
        raise HTTPException(404, "job not found")

    async def eventgen():
        q: asyncio.Queue[str] = info["queue"]
        while True:
            item = await q.get()
            if item == "[[DONE]]":
                yield "data: [[DONE]]\n\n"
                break
            if item.startswith("event:"):
                yield item
            else:
                for line in item.splitlines():
                    yield f"data: {line}\n"
                yield "\n"

    return StreamingResponse(eventgen(), media_type="text/event-stream")