# app/routers/storage.py
"""Storage module: disk usage overview + safe cleanup for outputs/."""
from __future__ import annotations

import os
import time
from pathlib import Path

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from app.deps import get_settings, get_templates
from app.services.targets import list_scopes

router = APIRouter(tags=["storage"])

CACHE_TTL = 60.0
_CACHE: dict = {"ts": 0.0, "payload": None}

# target -> (label, description)
SAFE_TARGETS = {
    "jobs_safe_in": ("Job inputs", "__jobs__/*_safe_in.txt — duplikat input per job, aman dihapus"),
    "jobs_all": ("Semua file job", "Seluruh isi __jobs__ (log + input), aman dihapus"),
    "raw": ("Raw tool outputs", "raw/*.urls — hasil mentah tool, sudah di-merge ke urls.txt"),
    "db": ("SQLite cache", "target.db* — cache DB, di-rebuild otomatis saat modul dibuka"),}


def _human(n) -> str:
    try:
        n = float(n)
    except Exception:
        return "-"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.0f} {units[i]}" if i == 0 else f"{n:.1f} {units[i]}"


def _walk_size(root: Path) -> tuple[int, int]:
    """Return (bytes, files) under root. Symlinks not followed."""
    total, files = 0, 0
    if not root.exists():
        return 0, 0
    if root.is_file():
        try:
            return root.stat().st_size, 1
        except OSError:
            return 0, 0
    stack = [root]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(Path(e.path))
                        elif e.is_file(follow_symlinks=False):
                            total += e.stat(follow_symlinks=False).st_size
                            files += 1
                    except OSError:
                        continue
        except OSError:
            continue
    return total, files


def _pattern_size(scope_dir: Path, sub: str, pattern: str) -> tuple[int, int]:
    total, files = 0, 0
    d = scope_dir / sub
    if not d.is_dir():
        return 0, 0
    for p in d.glob(pattern):
        try:
            if p.is_file():
                total += p.stat().st_size
                files += 1
        except OSError:
            continue
    return total, files


def _scope_usage(outputs_dir: Path, scope: str) -> dict:
    sd = outputs_dir / scope
    jobs_b, jobs_f = _walk_size(sd / "__jobs__")
    raw_b, raw_f = _walk_size(sd / "raw")
    cache_b, cache_f = _walk_size(sd / "__cache")
    db_b, db_f = 0, 0
    for name in ("target.db", "target.db-shm", "target.db-wal"):
        p = sd / name
        if p.is_file():
            try:
                db_b += p.stat().st_size
                db_f += 1
            except OSError:
                pass
    safe_in_b, safe_in_f = _pattern_size(sd, "__jobs__", "*_safe_in.txt")
    urls_b, urls_f = 0, 0
    try:
        pu = sd / "urls.txt"
        if pu.is_file():
            urls_b, urls_f = pu.stat().st_size, 1
    except OSError:
        pass
    cats_b, cats_f = 0, 0
    try:
        for p in sd.glob("*.txt"):
            if p.name == "urls.txt":
                continue
            try:
                if p.is_file():
                    cats_b += p.stat().st_size
                    cats_f += 1
            except OSError:
                continue
    except OSError:
        pass
    other_b, other_f = 0, 0
    for name in ("meta.json",):
        p = sd / name
        if p.is_file():
            try:
                other_b += p.stat().st_size
                other_f += 1
            except OSError:
                pass
    total_b = jobs_b + raw_b + cache_b + db_b + urls_b + cats_b + other_b
    reclaim_b = jobs_b + raw_b + db_b
    return {
        "scope": scope,
        "total": total_b, "total_h": _human(total_b),
        "jobs": jobs_b, "jobs_h": _human(jobs_b), "jobs_files": jobs_f,
        "safe_in": safe_in_b, "safe_in_h": _human(safe_in_b), "safe_in_files": safe_in_f,
        "raw": raw_b, "raw_h": _human(raw_b), "raw_files": raw_f,
        "urls": urls_b, "urls_h": _human(urls_b),
        "cats": cats_b, "cats_h": _human(cats_b), "cats_files": cats_f,
        "db": db_b, "db_h": _human(db_b),
        "cache": cache_b, "cache_h": _human(cache_b),
        "reclaim": reclaim_b, "reclaim_h": _human(reclaim_b),
    }


def _overview(outputs_dir: Path) -> dict:
    now = time.time()
    if _CACHE["payload"] and now - _CACHE["ts"] < CACHE_TTL:
        return _CACHE["payload"]
    scopes = [s for s in list_scopes(outputs_dir) if (outputs_dir / s).is_dir()]
    rows = [_scope_usage(outputs_dir, s) for s in scopes]
    rows.sort(key=lambda r: r["total"], reverse=True)
    payload = {
        "rows": rows,
        "total": sum(r["total"] for r in rows),
        "reclaim": sum(r["reclaim"] for r in rows),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cached": False,
    }
    payload["total_h"] = _human(payload["total"])
    payload["reclaim_h"] = _human(payload["reclaim"])
    _CACHE["payload"] = payload
    _CACHE["ts"] = now
    return payload


def _scope_files(outputs_dir: Path, scope: str, limit: int = 100) -> list[dict]:
    sd = outputs_dir / scope
    items: list[dict] = []

    def add(path: Path, label: str):
        try:
            if path.is_file():
                items.append({"path": label, "bytes": path.stat().st_size,
                              "human": _human(path.stat().st_size)})
        except OSError:
            pass

    for sub in ("__jobs__", "raw", "__cache"):
        d = sd / sub
        if d.is_dir():
            try:
                for p in sorted(d.iterdir()):
                    if p.is_file():
                        add(p, f"{sub}/{p.name}")
            except OSError:
                pass
    try:
        for p in sorted(sd.iterdir()):
            if p.is_file():
                add(p, p.name)
    except OSError:
        pass
    items.sort(key=lambda r: r["bytes"], reverse=True)
    return items[:limit]


def _do_cleanup(outputs_dir: Path, scope: str, target: str) -> dict:
    """Delete safe files. scope='__all__' applies to every scope."""
    scopes = [s for s in list_scopes(outputs_dir) if (outputs_dir / s).is_dir()] \
        if scope == "__all__" else [scope]
    removed_files, removed_bytes = 0, 0

    def _rm(p: Path):
        nonlocal removed_files, removed_bytes
        try:
            if p.is_file() and not p.is_symlink():
                removed_bytes += p.stat().st_size
                p.unlink()
                removed_files += 1
        except OSError:
            pass

    def _clean_one(sd: Path, one: str):
        if one == "jobs_safe_in":
            d = sd / "__jobs__"
            if d.is_dir():
                for p in d.glob("*_safe_in.txt"):
                    _rm(p)
        elif one == "jobs_all":
            d = sd / "__jobs__"
            if d.is_dir():
                for p in d.iterdir():
                    if p.is_file():
                        _rm(p)
        elif one == "raw":
            d = sd / "raw"
            if d.is_dir():
                for p in d.glob("*.urls"):
                    _rm(p)
        elif one == "db":
            for name in ("target.db", "target.db-shm", "target.db-wal"):
                _rm(sd / name)

    # "quick" = semua yang dihitung di kolom reclaim (tanpa pilih-pilih lagi)
    steps = ("jobs_all", "raw", "db") if target == "quick" else (target,)
    for s in scopes:
        sd = (outputs_dir / s).resolve()
        if outputs_dir.resolve() not in sd.parents:
            continue
        for one in steps:
            _clean_one(sd, one)
    _CACHE["ts"] = 0.0  # invalidate overview cache
    return {"files": removed_files, "bytes": removed_bytes,
            "human": _human(removed_bytes)}


@router.get("/storage", response_class=HTMLResponse)
def storage_page(request: Request, program: str | None = None,
                 scope: str | None = None, cleaned: str | None = None,
                 sort: str | None = None):
    settings = get_settings(request)
    templates = get_templates(request)
    outputs_dir = Path(settings.OUTPUTS_DIR)
    data = _overview(outputs_dir)

    # Group scopes by program (same grouping as homepage)
    from app.services.programs import load_programs
    try:
        saved = load_programs(outputs_dir) or {}
    except Exception:
        saved = {}
    scope_to_prog: dict[str, str] = {}
    for prog_name, prog_scopes in saved.items():
        for s in (prog_scopes or []):
            scope_to_prog[s] = prog_name
    for r in data["rows"]:
        r["program"] = scope_to_prog.get(r["scope"], "Default")

    prog_rows: list[dict] = []
    by_prog: dict[str, list[dict]] = {}
    for r in data["rows"]:
        by_prog.setdefault(r["program"], []).append(r)
    for prog_name in sorted(by_prog):
        prows = by_prog[prog_name]
        prog_rows.append({
            "program": prog_name,
            "n_scopes": len(prows),
            "total": sum(x["total"] for x in prows),
            "reclaim": sum(x["reclaim"] for x in prows),
        })
    for p in prog_rows:
        p["total_h"] = _human(p["total"])
        p["reclaim_h"] = _human(p["reclaim"])
    # Sorting program table: name asc/desc, total desc/asc, reclaim desc/asc
    sort = (sort or "name_asc").strip().lower()
    if sort not in ("name_asc", "name_desc", "total_asc", "total_desc",
                    "reclaim_asc", "reclaim_desc"):
        sort = "name_asc"
    reverse = sort.endswith("_desc")
    key = {"name": "program", "total": "total", "reclaim": "reclaim"}[sort.rsplit("_", 1)[0]]
    if key == "program":
        prog_rows.sort(key=lambda p: p["program"].lower(), reverse=reverse)
    else:
        prog_rows.sort(key=lambda p: (p[key], p["program"].lower()), reverse=reverse)

    # Scope table: only this program's scopes (or all if no program filter)
    scope_rows = [r for r in data["rows"] if program is None or r["program"] == program]
    if program is not None and program not in by_prog:
        program = None
        scope_rows = list(data["rows"])

    detail = None
    if scope and scope != "__all__":
        valid = [s for s in list_scopes(outputs_dir) if (outputs_dir / s).is_dir()]
        if scope in valid:
            detail = {"scope": scope,
                      "program": scope_to_prog.get(scope, "Default"),
                      "usage": _scope_usage(outputs_dir, scope),
                      "files": _scope_files(outputs_dir, scope)}
    ctx = {
        "request": request,
        "scope": None,
        "program_name": None,
        "module_name": "storage",
        "data": data,
        "prog_rows": prog_rows,
        "active_program": program,
        "active_sort": sort,
        "scope_rows": scope_rows,
        "detail": detail,
        "targets": SAFE_TARGETS,
        "cleaned": cleaned or "",
    }
    return templates.TemplateResponse("storage.html", ctx)


@router.post("/storage/cleanup")
def storage_cleanup(request: Request, scope: str = Form(...), target: str = Form(...)):
    settings = get_settings(request)
    outputs_dir = Path(settings.OUTPUTS_DIR)
    valid = set(s for s in list_scopes(outputs_dir) if (outputs_dir / s).is_dir())
    is_hx = (request.headers.get("hx-request") or "").lower() == "true"

    def _frag(title: str, body: str, ok: bool = True):
        color = "emerald" if ok else "rose"
        return HTMLResponse(
            f"""<div class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4"
                     onclick="if(event.target===this){{document.getElementById('cleanup-popup').innerHTML=''}}">
                  <div class="bg-white rounded-xl shadow-xl max-w-sm w-full p-6 space-y-3">
                    <h3 class="text-base font-semibold text-{color}-700">{title}</h3>
                    <p class="text-sm text-slate-600">{body}</p>
                    <div class="flex justify-end gap-2 pt-1">
                      <button class="btn text-sm" type="button"
                              onclick="document.getElementById('cleanup-popup').innerHTML=''">Tutup</button>
                      <button class="btn btn-primary text-sm" type="button"
                              onclick="document.getElementById('cleanup-popup').innerHTML='';location.reload()">Refresh angka</button>
                    </div>
                  </div>
                </div>""")

    if scope != "__all__" and scope not in valid:
        if is_hx:
            return _frag("Gagal", "Scope tidak dikenal.", ok=False)
        return RedirectResponse(url="/storage?cleaned=invalid-scope", status_code=303)
    if target not in SAFE_TARGETS and target != "quick":
        if is_hx:
            return _frag("Gagal", "Target tidak dikenal.", ok=False)
        return RedirectResponse(url="/storage?cleaned=invalid-target", status_code=303)
    # 'db' cleanup hanya per-scope (jangan global, berat rebuild-nya)
    if target == "db" and scope == "__all__":
        return RedirectResponse(url="/storage?cleaned=db-per-scope-only", status_code=303)
    res = _do_cleanup(outputs_dir, scope, target)
    label = "Cepat (job+raw+db)" if target == "quick" else SAFE_TARGETS[target][0]
    if is_hx:
        return _frag("Cleanup selesai",
                     f"{label} @ <code>{scope}</code>: {res['files']} file, {res['human']} dibebaskan.")
    msg = f"{label}:{scope}:{res['files']}files:{res['human']}"
    if scope != "__all__":
        try:
            from app.services.programs import load_programs
            saved = load_programs(outputs_dir) or {}
            prog = next((pn for pn, ss in saved.items() if scope in (ss or [])), "Default")
        except Exception:
            prog = "Default"
        nxt = f"/storage?cleaned={msg}&program={prog}&scope={scope}#detail"
    else:
        nxt = f"/storage?cleaned={msg}"
    return RedirectResponse(url=nxt, status_code=303)
