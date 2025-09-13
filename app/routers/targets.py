from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException, Query
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
import sys, os, re
from typing import Dict, Any
from app.core.modules import MODULE_FILES  


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

def _normalize_host(h: str) -> str:
    h = h.strip().lower()
    if h.endswith("."):  # buang trailing dot
        h = h[:-1]
    return h

def _merge_hosts(target: Path, newfile: Path) -> None:
    """Merge & dedup hostnames ke target (subdomains.txt)."""
    seen: set[str] = set()
    out_lines: list[str] = []

    def add_file(p: Path):
        if not p.exists():
            return
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                if not _HOST_RE.match(ln):
                    continue
                host = _normalize_host(ln)
                if host in seen:
                    continue
                seen.add(host)
                out_lines.append(host)

    add_file(target)
    add_file(newfile)

    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as out:
        out.write("\n".join(out_lines) + ("\n" if out_lines else ""))
        
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

# tambahkan di dekat _merge_urls
def _merge_lines(target: Path, newfile: Path):
    """
    Merge baris-baris plain text (mis. subdomain) → casefold, dedup.
    """
    seen = set()
    out = []
    def add(p: Path):
        if not p.exists():
            return
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                v = (ln.strip() or "").lower()
                if not v:
                    continue
                if v in seen:
                    continue
                seen.add(v)
                out.append(v)
    add(target)
    add(newfile)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as fo:
        fo.write("\n".join(out) + ("\n" if out else ""))

def _merge_subdomains(target: Path, newfile: Path):
    seen: set[str] = set()
    lines: list[str] = []

    def normalize_subdomain(s: str) -> str | None:
        s = s.strip().lower()
        if not s:
            return None
        # kalau full URL → ambil hostname
        if "://" in s:
            try:
                from urllib.parse import urlparse
                p = urlparse(s)
                return p.hostname
            except Exception:
                return None
        return s  # plain subdomain

    def add_file(p: Path):
        if not p.exists():
            return
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                sub = normalize_subdomain(ln)
                if not sub: 
                    continue
                if sub in seen:
                    continue
                seen.add(sub)
                lines.append(sub)

    add_file(target)
    add_file(newfile)

    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as out:
        out.write("\n".join(lines) + ("\n" if lines else ""))
        
def _tool_cmd(tool: str, scope: str, outputs_root: Path, *, module: str | None = None) -> list[str]:
    """
    Build command to run in the repo root (PYTHONPATH sudah di-set di _run_job).
    - gau / waymore        : collectors (stdout)
    - subfinder            : passive subdomain collector (stdout)
    - build                : python -m ReconLens ...
    - probe_subdomains     : python -m ReconLens.tools.probe_subdomains ...
    - probe_module         : python -m ReconLens.tools.probe_urls --input ... --source ...
    """
    if which("python") is None and which("python3") is None:
        raise FileNotFoundError("Python binary not found in PATH")

    # pilih interpreter
    py = os.environ.get("VIRTUAL_ENV")
    if py:
        py_exe = str(Path(py) / "bin" / ("python3" if (Path(py) / "bin/python3").exists() else "python"))
    else:
        py_exe = which("python3") or which("python") or "python3"

    out_dir = outputs_root / scope  # .../ReconLens/outputs/<scope>

    # ---- collectors (stdout) ----
    if tool == "gau":
        return ["gau", "--verbose", scope]

    if tool == "waymore":
        return ["waymore", "-i", scope, "-o", "-"]
    
    # ---- subdomain enumerator ----
    if tool == "subfinder":
        # Passive subdomain enum; -silent agar 1 host per baris, cocok untuk merge.
        # -all mengaktifkan seluruh sumber bawaan subfinder (pasif).
        return ["subfinder", "-d", scope, "-silent", "-all"]
    if tool == "amass":
        # amass enum -passive -d <scope> -o -
        return ["amass", "enum", "-passive", "-d", scope, "-o", "-"]
    if tool == "findomain":
        # stdout host/line
        return ["findomain", "-t", scope, "-q"]
    if tool == "bruteforce":
        # placeholder – nanti kita isi wordlist & resolvers
        return ["bash", "-lc", f"echo bruteforce-not-implemented-for {shlex.quote(scope)}"]
        
    # ---- build modules ----
    if tool == "build":
        # python -m ReconLens --scope ... --input outputs/<scope>/urls.txt --out outputs/<scope>
        return [
            py_exe, "-m", "ReconLens",
            "--scope", scope,
            "--input", str(out_dir / "urls.txt"),
            "--out",   str(out_dir),
        ]

    # ---- probing ----
    if tool == "probe_subdomains":
        # python -m ReconLens.tools.probe_subdomains --scope ... --input outputs/<scope>/subdomains.txt ...
        return [
            py_exe, "-m", "ReconLens.tools.probe_subdomains",
            "--scope", scope,
            "--input",   str(out_dir / "subdomains.txt"),
            "--outputs", str(outputs_root),
            "--concurrency", "20",
            "--timeout", "8",
            "--prefer-https",
            "--if-head-then-get",
        ]

    if tool == "probe_module":
        if not module:
            raise ValueError("probe_module requires module name")
        mod = module.lower()

        # input file: coba *_candidates.txt dulu; jika tidak ada, fallback ke *.txt
        candidates = out_dir / f"{mod}_candidates.txt"
        fallback   = out_dir / f"{mod}.txt"
        input_file = candidates if candidates.exists() else (fallback if fallback.exists() else candidates)

        # default mode per modul (bisa di-tune)
        default_mode = "GET" if mod in {"open_redirect"} else "GET"

        ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        )

        # python -m ReconLens.tools.probe_urls ...
        return [
            py_exe, "-m", "ReconLens.tools.probe_urls",
            "--scope",   scope,
            "--outputs", str(outputs_root),
            "--input",   str(input_file),
            "--source",  mod,
            "--mode",    default_mode,
            "--concurrency", "8",
            "--timeout",     "20",
            "--ua", ua,
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
    tmp_urls = jobs_dir / f"{job_id}.urls"    # dipakai juga utk hostnames
    raw_path = raw_dir  / f"{tool}-{_nowstamp()}.urls"

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
        outputs_root = out_dir.parent        # .../ReconLens/outputs
        package_root = outputs_root.parent   # .../ReconLens
        repo_root    = package_root.parent   # .../url_parser_real_world

        # optional module (for probe_module)
        module = job.get("module")
        cmd = _tool_cmd(tool, scope, outputs_root, module=module)

        # make sure ReconLens importable
        env = os.environ.copy()
        env["PYTHONPATH"] = (
            str(repo_root)
            + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(repo_root),
            env=env,
        )
        job["proc"] = proc
        q: asyncio.Queue[str] = job["queue"]

        # initial messages
        await q.put(f"$ {' '.join(shlex.quote(c) for c in cmd)}\n")
        await q.put(f"[info] cwd={repo_root}\n")
        await q.put(f"[info] PYTHONPATH={env['PYTHONPATH']}\n")
        await q.put(f"[info] raw → {raw_path}\n")
        await q.put("event: status\ndata: running\n\n")

        assert proc.stdout is not None
        is_domain_enum = tool in ("amass", "subfinder", "findomain")

        async for raw in proc.stdout:
            line = raw.decode("utf-8", "ignore").rstrip("\n")

            # selalu tulis ke log & raw arsip
            log_f.write(line + "\n"); log_f.flush()
            raw_f.write(line + "\n"); raw_f.flush()

            if tool in ("gau", "waymore"):
                # collector URL: baris yang mengandung skema
                if "://" in line:
                    urls_tmp_f.write(line + "\n"); urls_tmp_f.flush()
                    captured += 1

            elif is_domain_enum:
                # amass/subfinder: ambil token yang terlihat FQDN subdomain target
                # simple heuristic: kata yang berakhir ".<scope>" dan tidak mengandung skema
                for tok in line.split():
                    t = tok.strip().lower().strip(",;()[]{}<>")
                    if "://" in t:
                        continue
                    if t.endswith("." + scope.lower()):
                        urls_tmp_f.write(t + "\n"); urls_tmp_f.flush()
                        captured += 1

            # kirim ke UI (dibatasi lebar supaya tidak melebar)
            await q.put(line[:200] + "\n")

        rc = await proc.wait()
        await q.put(f"\n[exit] code={rc}\n")
        job["exit_code"] = rc

        # close tmp holders before post-processing
        urls_tmp_f.close()
        raw_f.close()

        if tool in ("gau", "waymore"):
            target = out_dir / "urls.txt"

            def _count_lines(p: Path) -> int:
                try:
                    with p.open("r", encoding="utf-8", errors="ignore") as f:
                        return sum(1 for _ in f)
                except Exception:
                    return 0

            before = _count_lines(target)
            _merge_urls(target, tmp_urls)   # dedup URL
            after  = _count_lines(target)
            added_unique = max(0, after - before)

            await q.put(
                f"[summary] captured={captured}  "
                f"unique_added={added_unique}  total_now={after}\n"
            )
            await q.put(f"[summary] merged → {target}\n")

        elif tool in ("subfinder", "amass", "findomain"):
            # merge hostnames ke subdomains.txt
            target = out_dir / "subdomains.txt"

            def _count(p: Path) -> int:
                try:
                    with p.open("r", encoding="utf-8", errors="ignore") as f:
                        return sum(1 for _ in f)
                except Exception:
                    return 0

            before = _count(target)
            _merge_subdomains(target, tmp_urls)  # dedup per-barís (host)
            after  = _count(target)
            added  = max(0, after - before)

            await q.put(f"[summary] captured={captured}  unique_added={added}  total_now={after}\n")
            await q.put(f"[summary] merged → {target}\n")

        elif tool == "build":
            await q.put(f"[summary] rebuild done. outputs → {out_dir}\n")

        elif tool in ("probe_subdomains", "probe_module"):
            if module:
                await q.put(f"[summary] probe (module={module}) done. outputs → {out_dir}\n")
            else:
                await q.put(f"[summary] probe done. outputs → {out_dir}\n")

        # signal selesai
        await q.put("event: status\ndata: done\n\n")

    except Exception as e:
        await job["queue"].put(f"[error] {e}\n")
        job["exit_code"] = -1
        await job["queue"].put("event: status\ndata: done\n\n")
    finally:
        try:
            log_f.close()
            if not urls_tmp_f.closed: urls_tmp_f.close()
            if not raw_f.closed: raw_f.close()
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
def collect_console(
    scope: str,
    tool: str,
    request: Request,
    module: str | None = None,  # <-- ambil dari query (?module=...)
):
    # izinkan tool yang kita dukung
    allowed = {"gau", "waymore", "build", "probe_subdomains", "probe_module", "subfinder", "amass", "findomain"}
    if tool not in allowed:
        return HTMLResponse("Unknown tool", status_code=404)

    settings  = get_settings(request)
    templates = get_templates(request)

    out_dir  = settings.OUTPUTS_DIR / scope
    urls_txt = out_dir / "urls.txt"

    return templates.TemplateResponse("collect_console.html", {
        "request": request,
        "scope": scope,
        "tool": tool,
        "module": module,          # <-- kirim ke template (boleh None)
        "urls_txt": str(urls_txt),
    })

# ============================================================
# Job endpoints (start / stream / cancel)
# ============================================================

@router.post("/{scope}/collect/{tool}/start")
async def collect_start(
    scope: str,
    tool: str,
    request: Request,
    module: str | None = Query(default=None),   # <— ambil ?module=...
):
    if tool not in ("gau", "waymore", "build", "probe_subdomains", "probe_module", "subfinder","amass","findomain"):
        raise HTTPException(404, "unknown tool")

    settings = get_settings(request)
    out_dir = settings.OUTPUTS_DIR / scope

    # jika sudah ada job aktif untuk tool+scope yang sama, reuse
    for jid, j in JOBS.items():
        if not j.get("done") and j["scope"] == scope and j["tool"] == tool and j.get("module") == module:
            return {"job_id": jid, "status": "running"}

    job_id = uuid.uuid4().hex
    q: asyncio.Queue[str] = asyncio.Queue()
    JOBS[job_id] = {
        "scope": scope,
        "tool": tool,
        "module": module,      # <— simpan modul (bisa None)
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
    
@router.get("/{scope}/probe/subdomains", response_class=HTMLResponse)
def probe_subdomains_console(scope: str, request: Request):
    settings = get_settings(request)
    templates = get_templates(request)
    out_dir = settings.OUTPUTS_DIR / scope
    return templates.TemplateResponse("collect_console.html", {
        "request": request,
        "scope": scope,
        "tool": "probe_subdomains",
        "urls_txt": str(out_dir / "subdomains.txt"),  # info saja di header
        "title": "Subdomains Probe",
    })

@router.get("/{scope}/probe/module/{module}", response_class=HTMLResponse)
def probe_module_console(scope: str, module: str, request: Request):
    settings = get_settings(request)
    templates = get_templates(request)
    out_dir = settings.OUTPUTS_DIR / scope
    return templates.TemplateResponse("collect_console.html", {
        "request": request,
        "scope": scope,
        "tool": "probe_module",
        "module": module,  # penting: diturunkan ke /start
        "urls_txt": "per-module file",  # info
        "title": f"Probe Module: {module}",
    })
    
@router.post("/{scope}/probe/subdomains/start")
async def probe_subdomains_start(scope: str, request: Request):
    settings = get_settings(request)
    out_dir = settings.OUTPUTS_DIR / scope

    # Jika ada job yang masih jalan untuk scope+tool sama, re-use
    for jid, j in JOBS.items():
        if not j.get("done") and j["scope"] == scope and j["tool"] == "probe_subdomains":
            return {"job_id": jid, "status": "running"}

    job_id = uuid.uuid4().hex
    q: asyncio.Queue[str] = asyncio.Queue()
    JOBS[job_id] = {"scope": scope, "tool": "probe_subdomains", "queue": q, "done": False, "exit_code": None}

    asyncio.create_task(_run_job(scope, "probe_subdomains", out_dir, job_id))
    return {"job_id": job_id, "status": "started"}

@router.post("/{scope}/probe/module/{module}/start")
async def probe_module_start(scope: str, module: str, request: Request):
    settings = get_settings(request)
    out_dir = settings.OUTPUTS_DIR / scope

    for jid, j in JOBS.items():
        if not j.get("done") and j["scope"] == scope and j["tool"] == "probe_module" and j.get("module") == module:
            return {"job_id": jid, "status": "running"}

    job_id = uuid.uuid4().hex
    q: asyncio.Queue[str] = asyncio.Queue()
    JOBS[job_id] = {"scope": scope, "tool": "probe_module", "module": module, "queue": q, "done": False, "exit_code": None}

    asyncio.create_task(_run_job(scope, "probe_module", out_dir, job_id))
    return {"job_id": job_id, "status": "started"}
