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

class HistoryQueue(asyncio.Queue):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.history = []

    async def put(self, item):
        self.history.append(item)
        await super().put(item)


JOBS_DIR = OUTPUTS_DIR / "__cache__" / "jobs"

def _save_job_to_disk(job_id: str, info: dict):
    try:
        JOBS_DIR.mkdir(parents=True, exist_ok=True)
        serializable = {
            "scope": info.get("scope"),
            "tool": info.get("tool"),
            "module": info.get("module"),
            "host": info.get("host"),
            "wordlists": info.get("wordlists"),
            "done": info.get("done", False),
            "exit_code": info.get("exit_code"),
            "log_path": info.get("log_path"),
            "raw_path": info.get("raw_path"),
            "probe_mode": info.get("probe_mode", "HEAD"),
            "only_alive": info.get("only_alive", False),
            "pid": info.get("pid"),
        }
        with open(JOBS_DIR / f"{job_id}.json", "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)
    except Exception as e:
        print(f"[WARN] Failed to save job metadata to disk: {e}", flush=True)

def _load_job_from_disk(job_id: str) -> dict | None:
    path = JOBS_DIR / f"{job_id}.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        pid = data.get("pid")
        done = data.get("done", False)
        if not done and pid:
            is_running = False
            try:
                os.kill(pid, 0)
                is_running = True
            except OSError:
                pass
            if not is_running:
                data["done"] = True
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)

        q = HistoryQueue()
        log_path = data.get("log_path")
        if log_path and os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="ignore") as lf:
                for line in lf:
                    q.history.append(line.rstrip("\n"))
        
        if data.get("done"):
            q.history.append("[[DONE]]")

        info = {
            "queue": q,
            "proc": None,
            "done": data.get("done", False),
            "exit_code": data.get("exit_code"),
            "scope": data.get("scope"),
            "tool": data.get("tool"),
            "module": data.get("module"),
            "host": data.get("host"),
            "wordlists": data.get("wordlists"),
            "log_path": log_path,
            "urls_path": data.get("urls_path"),
            "raw_path": data.get("raw_path"),
            "probe_mode": data.get("probe_mode", "HEAD"),
            "only_alive": data.get("only_alive", False),
            "pid": pid,
        }
        JOBS[job_id] = info
        return info
    except Exception as e:
        print(f"[WARN] Failed to load job metadata from disk: {e}", flush=True)
        return None


def _new_job(scope: str, tool: str, module: str | None = None,
             host: str | None = None, wordlists: str | None = None, custom_cmd: str | None = None, probe_mode: str = "HEAD", only_alive: bool = False) -> str:
    """Create a new job entry and initialize its async queue with history recording."""
    jid = os.urandom(12).hex()
    info = {
        "queue": HistoryQueue(),
        "proc": None,
        "done": False,
        "exit_code": None,
        "scope": scope,
        "tool": tool,
        "module": module,
        "host": host,
        "wordlists": wordlists,
        "custom_cmd": custom_cmd,
        "probe_mode": probe_mode,
        "only_alive": only_alive,
        "pid": None,
    }
    JOBS[jid] = info
    _save_job_to_disk(jid, info)
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

        # --- Scope filtering for safe execution ---
        from app.services.scope_evaluator import load_scope_rules, is_in_scope
        scope_rules = load_scope_rules(out_dir)
        input_override = None

        if tool in ["build", "probe_subdomains", "probe_module", "dirsearch"]:
            primary_input = None
            if tool == "build":
                primary_input = out_dir / "urls.txt"
            elif tool == "probe_subdomains" or (tool == "probe_module" and job.get("module") == "subdomains"):
                primary_input = out_dir / "subdomains.txt"
            elif tool == "probe_module":
                mod = (job.get("module") or "").lower()
                candidates = out_dir / f"{mod}_candidates.txt"
                fallback   = out_dir / f"{mod}.txt"
                primary_input = candidates if candidates.exists() else fallback
            elif tool == "dirsearch":
                # For dirsearch, if it runs on a single host, we can still filter it just in case
                if host and not is_in_scope(host, scope_rules):
                    await q.put(f"[WARN] Host {host} is Out of Scope! Execution cancelled.\n")
                    job["exit_code"] = 1
                    return
            
            # If we found a primary input, filter it to a safe temp file
            if primary_input and primary_input.exists():
                safe_input = jobs_dir / f"{job_id}_safe_in.txt"
                filtered_out = 0
                total_in = 0
                with primary_input.open("r", encoding="utf-8", errors="ignore") as f_in, safe_input.open("w", encoding="utf-8") as f_out:
                    for line in f_in:
                        u = line.strip()
                        if not u: continue
                        total_in += 1
                        if is_in_scope(u, scope_rules):
                            f_out.write(u + "\n")
                        else:
                            filtered_out += 1
                
                if filtered_out > 0:
                    await q.put(f"[INFO] Scope Filter: Removed {filtered_out} out-of-scope targets from {total_in} total.\n")
                input_override = safe_input

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
            custom_cmd=job.get("custom_cmd"),
            probe_mode=job.get("probe_mode", "HEAD"),
            only_alive=job.get("only_alive", False),
            input_override=input_override,
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

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(project_root),
            env=env,
        )
        job["proc"] = proc
        job["pid"] = proc.pid
        _save_job_to_disk(job_id, job)
        await q.put("event: status\ndata: running\n\n")

        # Stream stdout (akan memunculkan "Classifying: ...", tabel ascii, dll dari CLI)
        assert proc.stdout is not None
        preview_count = 0
        preview_capped = False

        async def read_lines(stream: asyncio.StreamReader):
            buffer = bytearray()
            while True:
                chunk = await stream.read(8192)
                if not chunk:
                    if buffer:
                        yield bytes(buffer)
                    break
                buffer.extend(chunk)
                while b'\n' in buffer:
                    idx = buffer.index(b'\n')
                    yield bytes(buffer[:idx])
                    del buffer[:idx + 1]
                if len(buffer) > 1024 * 1024:  # 1MB limit protection
                    yield bytes(buffer[:1024 * 1024])
                    del buffer[:1024 * 1024]

        with open(log_path, "w", encoding="utf-8", errors="ignore") as log_f, \
             open(tmp_urls, "w", encoding="utf-8", errors="ignore") as urls_f, \
             open(raw_path, "w", encoding="utf-8", errors="ignore") as raw_f:

            async for raw in read_lines(proc.stdout):
                line = raw.decode("utf-8", "ignore").rstrip("\r\n")
                log_f.write(line + "\n"); log_f.flush()
                raw_f.write(line + "\n"); raw_f.flush()

                # Capture heuristics
                if tool == "dirsearch":
                    pass
                elif tool in ("nuclei_takeover", "subzy_takeover", "subjack_takeover"):
                    if line.strip():
                        urls_f.write(line.strip() + "\n"); urls_f.flush()
                        captured += 1
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
        _save_job_to_disk(job_id, job)
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
        _save_job_to_disk(job_id, job)
        await q.put("event: status\ndata: done\n\n")
    finally:
        try:
            from app.services.db_sync import sync_target
            await asyncio.to_thread(sync_target, outputs_root, scope)
        except Exception as e:
            print(f"[WARN] Failed to sync SQLite DB: {e}")
            
        job["done"] = True
        _save_job_to_disk(job_id, job)
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
    if tool in ("gau", "waymore", "urlfinder"):
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

    elif tool in ("nuclei_takeover", "subzy_takeover", "subjack_takeover"):
        target = out_dir / "takeovers.txt"
        before = read_text_lines(target) if target.exists() else 0
        from app.routers.targets.utils import merge_lines
        merge_lines(target, tmp_urls)
        after = read_text_lines(target)
        added = max(0, after - before)
        update_last_scan(scope, tool, out_dir.parent)
        await q.put(f"[summary] captured={captured}  unique_takeovers={added}  total_now={after}\n")

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
    cmd_b64 = request.query_params.get("cmd_b64") or ""

    return templates.TemplateResponse("admin/collect_console.html", {
        "request": request,
        "scope": scope,
        "tool": tool,
        "module": module,
        "last_scans": last_scans,
        "host": host,
        "wordlist": wordlist,
        "cmd_b64": cmd_b64,
    })


@router.post("/{scope}/collect/{tool}/start")
async def collect_start(scope: str, tool: str, request: Request):
    """Start a recon job (gau, waymore, dirsearch, etc.)"""
    module = request.query_params.get("module")
    host = request.query_params.get("host") or ""
    wl_name = request.query_params.get("wordlist") or "dicc.txt"
    probe_mode = request.query_params.get("mode") or "HEAD"
    only_alive = request.query_params.get("only_alive") == "true"

    if tool == "dirsearch":
        if not host:
            return JSONResponse({"ok": False, "error": "host param required"}, status_code=400)
        wl_path = resolve_wordlist(wl_name)
        if wl_path is None:
            wl_name = "dicc.txt"

        if not host_in_scope(host, scope):
            return JSONResponse({"ok": False, "error": "host not in scope"}, status_code=400)

        jid = _new_job(scope, tool, host=normalize_host(host), wordlists=wl_name)
    elif tool == "custom_bash":
        cmd_b64 = request.query_params.get("cmd_b64") or ""
        import base64
        try:
            raw_cmd = base64.b64decode(cmd_b64).decode("utf-8")
        except Exception:
            raw_cmd = ""
        if not raw_cmd:
            return JSONResponse({"ok": False, "error": "missing cmd_b64 parameter"}, status_code=400)
        jid = _new_job(scope, tool, custom_cmd=raw_cmd, probe_mode=probe_mode, only_alive=only_alive)
    else:
        jid = _new_job(scope, tool, module=module, host=host, probe_mode=probe_mode, only_alive=only_alive)

    out_dir = OUTPUTS_DIR / scope
    settings = get_settings(request)
    asyncio.create_task(_run_job(scope, tool, out_dir, jid, settings=settings))
    return JSONResponse({"ok": True, "job_id": jid})


@router.post("/{scope}/collect/{tool}/cancel")
async def collect_cancel(scope: str, tool: str, job: str):
    """Cancel a running job by sending SIGINT."""
    info = JOBS.get(job)
    if not info:
        info = _load_job_from_disk(job)
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
    else:
        pid = info.get("pid")
        if pid:
            try:
                os.kill(pid, signal.SIGINT)
            except Exception:
                try:
                    os.kill(pid, signal.SIGTERM)
                except Exception:
                    pass
    return JSONResponse({"ok": True})


@router.get("/{scope}/collect/{tool}/stream")
async def collect_stream(scope: str, tool: str, job: str):
    """Stream job output via Server-Sent Events with history re-attachment."""
    info = JOBS.get(job)
    if not info:
        info = _load_job_from_disk(job)
    if not info:
        raise HTTPException(404, "job not found")

    async def eventgen():
        q = info["queue"]
        history = getattr(q, "history", [])
        index = 0
        while True:
            if index < len(history):
                item = history[index]
                index += 1
                if item == "[[DONE]]":
                    yield "data: [[DONE]]\n\n"
                    break
                if item.startswith("event:"):
                    yield item
                else:
                    for line in item.splitlines():
                        yield f"data: {line}\n"
                    yield "\n"
            else:
                # If job is fully complete and we read all history
                if info.get("done") and index >= len(history):
                    yield "data: [[DONE]]\n\n"
                    break
                await asyncio.sleep(0.1)

    return StreamingResponse(eventgen(), media_type="text/event-stream")


@router.get("/{scope}/active-jobs")
async def get_active_jobs(scope: str):
    """Get active running jobs for the scope."""
    # Recover any lost active jobs from disk
    if JOBS_DIR.exists():
        try:
            for p in JOBS_DIR.glob("*.json"):
                jid = p.stem
                if jid not in JOBS:
                    _load_job_from_disk(jid)
        except Exception as e:
            print(f"[WARN] Error restoring active jobs from disk cache: {e}", flush=True)

    active = []
    for jid, info in JOBS.items():
        if info.get("scope") == scope and not info.get("done"):
            # Check if process is still running
            pid = info.get("pid")
            is_running = False
            if pid:
                try:
                    os.kill(pid, 0)
                    is_running = True
                except OSError:
                    pass
            else:
                proc = info.get("proc")
                is_running = proc is None or proc.returncode is None
            
            if is_running:
                active.append({
                    "job_id": jid,
                    "tool": info.get("tool"),
                    "module": info.get("module"),
                    "host": info.get("host"),
                })
    return JSONResponse(active)