# app/routers/targets.py
from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import signal
from datetime import datetime, timezone
from pathlib import Path
from shutil import which
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, quote

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from ..deps import get_settings, get_templates
from .subdomains import (
    _alive_flag,
    _resolve_subdomains_file,
    _iter_hosts_filtered,
    _paginate_iter,
    _decorate_last_probe,
    load_enrich,
)
from .subdomains import subdomains_page
from ..services.wordlists import list_wordlists, get_wordlists_dir, resolve_wordlist

# === Paths / Templating =====================================================

BASE_DIR = Path(__file__).resolve().parents[2]  # .../ReconLens
APP_DIR = BASE_DIR / "app"
TEMPLATES = Jinja2Templates(directory=str(APP_DIR / "templates"))

OUTPUTS_DIR = BASE_DIR / "outputs"  # outputs/<scope>

router = APIRouter(prefix="/targets", tags=["targets"])

# === In-memory job registry ==================================================

JOBS: Dict[str, Dict[str, Any]] = {}
# JOBS[job_id] = {
#   "queue": asyncio.Queue[str], "proc": Process, "done": bool, "exit_code": int,
#   "scope": str, "tool": str, "module": Optional[str],
#   "log_path": str, "urls_path": str, "raw_path": str,
# }

# --- dirsearch parsing & url-enrich -----------------------------------------
_DIR_LINE_RE = re.compile(
    r"\[(\d{2}:\d{2}:\d{2})\]\s+(\d{3})\s*-\s*([0-9.]+\s*[KMG]?B)\s*-\s*(https?://\S+?)(?:\s*->\s*(\S+))?\s*$",
    re.IGNORECASE,
)

def _size_to_bytes(size_str: str) -> Optional[int]:
    """
    Convert '1KB', '12.3 MB', '456B' -> int bytes. Returns None if unknown.
    """
    if not size_str:
        return None
    s = size_str.strip().upper().replace(" ", "")
    try:
        if s.endswith("KB"):
            return int(float(s[:-2]) * 1024)
        if s.endswith("MB"):
            return int(float(s[:-2]) * 1024 * 1024)
        if s.endswith("GB"):
            return int(float(s[:-2]) * 1024 * 1024 * 1024)
        if s.endswith("B"):
            return int(float(s[:-1]))
        # fallback: plain number
        return int(float(s))
    except Exception:
        return None

def _parse_dirsearch_line(line: str) -> Optional[dict]:
    """
    Parse a single dirsearch result line:
      [13:11:00] 200 -  12KB - https://example.com/admin/
      [13:11:05] 301 -   0B  - https://a/old  ->  https://a/new
    Returns {code:int, size:int|None, url:str, redirect:str|None} or None if not a result line.
    """
    m = _DIR_LINE_RE.search(line)
    if not m:
        return None
    _, code_s, size_s, url, redirect = m.groups()
    code = int(code_s)
    size = _size_to_bytes(size_s)
    return {"code": code, "size": size, "url": url, "redirect": redirect}

def _url_enrich_path(outputs_root: Path, scope: str) -> Path:
    cache_dir = outputs_root / scope / "__cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "url_enrich.json"

def _load_url_enrich(outputs_root: Path, scope: str) -> dict:
    p = _url_enrich_path(outputs_root, scope)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}

def _save_url_enrich(outputs_root: Path, scope: str, data: dict) -> None:
    p = _url_enrich_path(outputs_root, scope)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def _update_url_enrich_from_dirsearch(outputs_root: Path, scope: str, url: str, code: int, size: Optional[int]) -> None:
    """
    Upsert per-URL enrich (code, size, last_probe, alive). Title/ctype dibiarkan kosong (bisa diisi nanti).
    """
    data = _load_url_enrich(outputs_root, scope)
    rec = data.get(url) or {}
    rec.update({
        "mode": "GET", #untuk saat ini inputan dari dirsearch otomatis diberi value mode = GET 
        "code": code,
        "size": size,
        "last_probe": datetime.now(timezone.utc).isoformat(),
        "alive": (200 <= code < 500),   # definisi sederhana
        # jangan set 'title' / 'content_type' di sini—biarin kosong
    })
    data[url] = rec
    _save_url_enrich(outputs_root, scope, data)
    
# === Helpers ================================================================
def _safe_read_json(p: Path) -> dict:
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

def _host_no_port(netloc: str) -> str:
    """lowercase & drop :port from netloc"""
    if not netloc:
        return ""
    h = netloc.lower()
    if ":" in h:
        h = h.split(":", 1)[0]
    return h

def _all_hosts_for_scope(outputs_root: Path, scope: str) -> list[str]:
    """
    Ambil SELURUH host dari outputs/<scope>/__cache/subdomains_enrich.json,
    normalisasi ke host tanpa port. Tidak memfilter 'alive'.
    """
    cache = outputs_root / scope / "__cache" / "subdomains_enrich.json"
    data = _safe_read_json(cache)
    res: set[str] = set()
    for k, rec in (data or {}).items():
        final = rec.get("final_url") or k
        u = final if "://" in str(final) else f"https://{final}"
        try:
            p = urlparse(u)
            host = (p.netloc or p.path or "").split(":")[0].lower()
            if host:
                res.add(host)
        except Exception:
            pass
    return sorted(res)
    
def _fmt_size_human(v: Any) -> Optional[str]:
    """
    Convert byte count to human string. Accepts int/float/str.
    Returns None if unknown/invalid.
    """
    if v in (None, "", "-", "None"):
        return None
    try:
        n = int(float(v))
    except Exception:
        return None
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    # 0/1 decimal for KB+; none for bytes
    return (f"{f:.1f} {units[i]}" if i > 0 else f"{int(f)} {units[i]}")


def _fmt_last_probe(v: Any) -> Optional[str]:
    """
    Normalize last_probe into 'YYYY-MM-DD HH:MM:SS' (UTC).
    Accepts ISO strings or epoch seconds (int/str).
    """
    if v in (None, "", "-", "None"):
        return None
    # ISO 8601 string?
    if isinstance(v, str) and ("T" in v or "-" in v and ":" in v):
        # just trim 'T' and timezone suffix for compact view
        s = v.replace("T", " ")
        # cut off fractional seconds/timezone if present
        # e.g. "2025-09-14 04:42:41.798625+00:00" -> "2025-09-14 04:42:41"
        m = re.match(r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})", s)
        return m.group(1) if m else s
    # epoch seconds?
    try:
        sec = int(float(v))
        dt = datetime.fromtimestamp(sec, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(v)
        
def _nowstamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _read_text_lines(p: Path) -> int:
    try:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def _safe_json_load(p: Path) -> Dict[str, Any]:
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_meta(scope: str, **updates):
    out_dir = OUTPUTS_DIR / scope
    meta_path = out_dir / "meta.json"
    meta = _safe_json_load(meta_path)
    # shallow update
    for k, v in updates.items():
        if isinstance(v, dict) and isinstance(meta.get(k), dict):
            meta[k].update(v)
        else:
            meta[k] = v
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

def _update_last_scan(scope: str, tool: str):
    utc = datetime.now(timezone.utc).isoformat()
    _save_meta(scope, last_scans={tool: utc})


def _merge_urls(target: Path, incoming: Path):
    """
    Merge URL list (one per line), case-sensitive unique (URLs).
    """
    seen = set()
    if target.exists():
        with target.open("r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.rstrip("\n")
                if ln:
                    seen.add(ln)
    # append new
    with incoming.open("r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            ln = ln.rstrip("\n")
            if not ln:
                continue
            if ln not in seen:
                seen.add(ln)

    tmp = target.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as out:
        for u in sorted(seen):
            out.write(u + "\n")
    tmp.replace(target)


_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

def _merge_hostnames(target: Path, incoming: Path):
    """
    Merge hostname list (one per line). Tolerant: kalau baris URL penuh, ambil netloc-nya.
    """
    from urllib.parse import urlparse

    def normalize_host(line: str) -> Optional[str]:
        s = line.strip()
        if not s:
            return None
        if "://" in s:
            try:
                h = urlparse(s).netloc.lower()
            except Exception:
                return None
        else:
            h = s.lower()
        h = h.strip(".")
        # basic validation
        if not _HOST_RE.match(h):
            return None
        return h

    seen = set()
    if target.exists():
        with target.open("r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                h = normalize_host(ln)
                if h:
                    seen.add(h)

    with incoming.open("r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            h = normalize_host(ln)
            if h and h not in seen:
                seen.add(h)

    tmp = target.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as out:
        for h in sorted(seen):
            out.write(h + "\n")
    tmp.replace(target)


def _human_size(n: int) -> int:
    return n


def _list_category_files(scope: str) -> List[str]:
    """
    Kategori baru (engine baru).
    """
    out_dir = OUTPUTS_DIR / scope
    # daftar kategori yang kita kenal; kalau ada file lain *.txt akan ikut juga sebagai dynamic
    known = {
        "subdomains","auth_login", "admin_panel", "api", "upload", "download_dump",
        "debug_dev", "docs_swagger", "config_backup_source",
        "sensitive_functionality", "monitoring", "payments",
        "static_assets", "file_disclosure", "other",
    }
    files = []
    for p in sorted(out_dir.glob("*.txt")):
        name = p.stem
        if name == "urls":  # corpus
            continue
        # terima semua kategori .txt agar dinamis
        files.append(name)
    # prioritaskan urutan: subdomains (kalau ada), lalu known, lalu sisanya
    if "subdomains" in files:
        files.remove("subdomains")
        files = ["subdomains"] + files
    # unique
    seen = set()
    ordered = []
    for k in (["subdomains"] + sorted(known - {"subdomains"}) + files):
        if k not in seen and (out_dir / f"{k}.txt").exists():
            seen.add(k)
            ordered.append(k)
    return ordered

def _stat_file(p: Path) -> tuple[int, int]:
    if not p.exists():
        return 0, 0
    try:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            lines = sum(1 for _ in f)
        return lines, p.stat().st_size
    except Exception:
        return 0, p.stat().st_size if p.exists() else 0
        
def _gather_stats(scope: str) -> Dict[str, Any]:
    out = []
    out_dir = OUTPUTS_DIR / scope
    if not out_dir.exists():
        return {"stats": [], "urls_count": 0, "dash": {}}

    # urls.txt
    urls_path = out_dir / "urls.txt"
    urls_count = _read_text_lines(urls_path)

    # kategori dinamis (file .txt hasil klasifikasi baru)
    modules = _list_category_files(scope)  # ini boleh tetap seperti existing
    for mod in modules:
        p = out_dir / f"{mod}.txt"
        lines, size = _stat_file(p)
        row = {
            "module": mod,
            "file": p.name,
            "lines": lines,
            "size_bytes": size,
        }
        if mod == "subdomains":
            row["hosts"] = lines
        out.append(row)

    # ⬇️ force inject/overwrite SUBDOMAINS dari file aktual
    sub_p = out_dir / "subdomains.txt"
    sub_lines, sub_bytes = _stat_file(sub_p)
    # cari kalau sudah ada entry 'subdomains' → overwrite; kalau belum → append
    replaced = False
    for row in out:
        if row.get("module") == "subdomains":
            row.update({"file": sub_p.name, "lines": sub_lines, "hosts": sub_lines, "size_bytes": sub_bytes})
            replaced = True
            break
    if not replaced:
        out.insert(0, {  # taruh di depan biar gampang terlihat
            "module": "subdomains",
            "file": sub_p.name,
            "lines": sub_lines,
            "hosts": sub_lines,
            "size_bytes": sub_bytes,
        })

    # dashboard/meta (biarkan existing)
    meta = _safe_json_load(out_dir / "meta.json")
    dash = {
        "totals": meta.get("totals", {}),
        "status_counts": meta.get("status_counts", {}),
        "ctypes": meta.get("ctypes", {}),
        "last_probe_iso": (meta.get("last_scans") or {}).get("probe", None),
        "last_scans": meta.get("last_scans", {}),
    }
    return {"stats": out, "urls_count": urls_count, "dash": dash}
    
def _update_dirsearch_last(out_dir: Path, host: str):
    """Update timestamp per-host untuk dirsearch -> __cache/dirsearch_last.json"""
    cache_dir = out_dir / "__cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    p = cache_dir / "dirsearch_last.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except Exception:
        data = {}
    data[host] = datetime.now(timezone.utc).isoformat()
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    
# --- host helpers ------------------------------------------------------------

def _normalize_host(val: str) -> str:
    """Terima hostname atau URL penuh → kembalikan hostname bersih (lower, strip dot)."""
    s = (val or "").strip()
    if not s:
        return ""
    try:
        if "://" in s:
            from urllib.parse import urlparse
            netloc = urlparse(s).netloc
            s = netloc or s
    except Exception:
        pass
    s = s.lower().strip(".")
    # buang kredensial kalau ada (user:pass@host)
    if "@" in s:
        s = s.rsplit("@", 1)[-1]
    # buang port
    if ":" in s:
        s = s.split(":", 1)[0]
    return s

def _host_in_scope(host: str, scope: str) -> bool:
    """True kalau host == scope atau host berakhir dengan .scope"""
    h = _normalize_host(host)
    sc = (scope or "").lower().lstrip(".")
    if not h or not sc:
        return False
    return h == sc or h.endswith("." + sc)


# === Pages ==================================================================
def load_url_enrich(outputs_dir: Path, scope: str) -> Dict[str, Dict[str, Any]]:
    """
    Load per-URL enrich dari __cache/url_enrich.json
    Return dict: { url_or_final_url: record }
    - Tahan format fleksibel (list of dicts ATAU dict mapping url->rec).
    - Index-kan dua kunci: 'url' dan 'final_url' jika ada.
    """
    cache = outputs_dir / scope / "__cache" / "url_enrich.json"
    if not cache.exists():
        return {}
    try:
        raw = json.loads(cache.read_text(encoding="utf-8"))
    except Exception:
        return {}

    idx: Dict[str, Dict[str, Any]] = {}

    def _put(key: Optional[str], rec: Dict[str, Any]):
        if not key or not isinstance(key, str):
            return
        k = key.strip()
        if not k:
            return
        idx[k] = rec

    if isinstance(raw, dict):
        # bisa jadi sudah {url: rec}
        for k, v in raw.items():
            if isinstance(v, dict):
                _put(k, v)
                _put(v.get("final_url"), v)
            elif isinstance(v, (str, int, float, list)):
                # kalau value bukan dict, lewati
                continue
            # bila dict punya field 'url', indekskan juga
            if isinstance(v, dict) and v.get("url"):
                _put(v.get("url"), v)

    elif isinstance(raw, list):
        for rec in raw:
            if not isinstance(rec, dict):
                continue
            _put(rec.get("url"), rec)
            _put(rec.get("final_url"), rec)

    return idx
    
@router.get("/{scope}", response_class=HTMLResponse)
async def target_detail(request: Request, scope: str):    
    stats_pack = _gather_stats(scope)
    stats = stats_pack["stats"]
    urls_count = stats_pack["urls_count"]
    dash = stats_pack["dash"]

    # NEW: total module lines & flag has_modules
    total_module_lines = sum((s.get("lines") or 0) for s in stats)
    has_modules = total_module_lines > 0
    stats_map = { row["module"]: row for row in stats }
    
    ctx = {
        "request": request,
        "scope": scope,
        "stats": stats,
        "urls_count": urls_count,
        "stats_map": stats_map,
        "dash": dash,
        "has_modules": has_modules,
        # has_timeago bisa kamu set True kalau filter terpasang
        "has_timeago": False,
    }
    return TEMPLATES.TemplateResponse("target_detail.html", ctx)


@router.get("/{scope}/{module}", response_class=HTMLResponse)
async def module_view(request: Request, scope: str, module: str, q: str = ""):
    mod = (module or "").strip().lower()

    if mod == "subdomains":
        return await subdomains_page(scope=scope, request=request)

    settings  = get_settings(request)
    templates = get_templates(request)
    outputs_root = Path(settings.OUTPUTS_DIR)
    out_dir   = outputs_root / scope
    page_url  = f"/targets/{scope}/{mod}"
    discovery_host_options = _all_hosts_for_scope(outputs_root, scope)
    wordlists = list_wordlists()
    path = out_dir / f"{mod}.txt"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Module file not found")

    # ---------- filters ----------
    page      = int(request.query_params.get("page") or 1)
    page_size = int(request.query_params.get("page_size") or 50)
    if page_size < 1: page_size = 50

    http_class = (request.query_params.get("http_class") or "").strip().lower()
    codes_str  = (request.query_params.get("codes") or "").strip()
    ctype_sub  = (request.query_params.get("ctype") or "").strip().lower()
    scheme_f   = (request.query_params.get("scheme") or "").strip().lower()
    host_f     = (request.query_params.get("host") or "").strip().lower()
    # NEW: HTTP Method filter (normalize to UPPER; treat '(any)' as empty)
    method_filter = (request.query_params.get("method") or "").strip().upper()
    if method_filter in ("(ANY)", "ANY"):
        method_filter = ""

    try:
        min_size = int(request.query_params.get("min_size")) if request.query_params.get("min_size") else None
    except Exception:
        min_size = None
    try:
        max_size = int(request.query_params.get("max_size")) if request.query_params.get("max_size") else None
    except Exception:
        max_size = None

    codes_set = set()
    if codes_str:
        for tok in codes_str.replace(";", ",").split(","):
            tok = tok.strip()
            if tok.isdigit():
                codes_set.add(int(tok))

    # ---------- load corpus + build host options ----------
    raw_items: list[str] = []
    host_options_set: set[str] = set()

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            s = (ln or "").strip()
            if not s:
                continue
            if q and q.lower() not in s.lower():
                continue
            raw_items.append(s)
            # collect distinct hosts for the dropdown (from the module file)
            try:
                p = urlparse(s)
                h = (p.netloc or "").lower()
                if h:
                    host_options_set.add(h)
            except Exception:
                pass

    host_options = sorted(host_options_set)

    # ---------- enrich ----------
    enrich_host  = load_enrich(outputs_root, scope) or {}
    enrich_url   = load_url_enrich(outputs_root, scope) or {}

    def pick(*vals):
        for v in vals:
            if v not in (None, "", "-", "None"):
                return v
        return None

    # ---------- apply filters BEFORE pagination ----------
    filtered_rows: list[dict] = []
    for s in raw_items:
        try:
            p = urlparse(s)
        except Exception:
            p = None

        host = (p.netloc.lower() if p else "")
        if host_f and host != host_f:
            continue

        rec_host = enrich_host.get(host) if host else None
        rec_url  = (
            enrich_url.get(s)
            or (enrich_url.get(s.rstrip("/")) if s.endswith("/") else None)
            or enrich_url.get(s + "/")
        )

        # scheme filter
        scheme = (
            (rec_url.get("scheme") if rec_url and rec_url.get("scheme") else None)
            or (rec_host.get("scheme") if rec_host and rec_host.get("scheme") else None)
            or (p.scheme if p and p.scheme else "https")
        )
        if scheme_f and scheme_f not in ("", "(any)", "any"):
            if scheme != scheme_f:
                continue

        # NEW: method extraction + filter
        method_val = pick(
            (rec_url.get("method") if rec_url else None),
            (rec_url.get("mode")   if rec_url else None),
            (rec_host.get("method") if rec_host else None),
            (rec_host.get("mode")   if rec_host else None),
        )
        method_val_u = (str(method_val).upper() if method_val else "")
        if method_filter and method_val_u != method_filter:
            continue

        code  = pick(rec_url.get("code")  if rec_url else None,  rec_host.get("code")  if rec_host else None)
        size  = pick(rec_url.get("size")  if rec_url else None,  rec_host.get("size")  if rec_host else None)
        title = pick(rec_url.get("title") if rec_url else None,  rec_host.get("title") if rec_host else None)
        ctype = pick(rec_url.get("content_type") if rec_url else None,
                     rec_host.get("content_type") if rec_host else None)
        lastp = pick(rec_url.get("last_probe")  if rec_url else None,
                     rec_host.get("last_probe")  if rec_host else None,
                     rec_url.get("ts") if rec_url else None,
                     rec_host.get("ts") if rec_host else None)

        try: code_i = int(code) if code is not None else None
        except: code_i = None
        try: size_i = int(size) if size is not None else None
        except: size_i = None

        if codes_set:
            if code_i is None or code_i not in codes_set:
                continue
        else:
            if http_class in ("2xx","3xx","4xx","5xx"):
                if code_i is None or (code_i // 100) != int(http_class[0]):
                    continue

        if ctype_sub and (not ctype or ctype_sub not in str(ctype).lower()):
            continue
        if min_size is not None and (size_i is None or size_i < min_size):
            continue
        if max_size is not None and (size_i is None or size_i > max_size):
            continue

        final = s
        if p and not p.scheme and scheme:
            final = f"{scheme}://{host}{p.path or '/'}"
            if p.query:
                final += f"?{p.query}"
            if p.fragment:
                final += f"#{p.fragment}"

        alive  = (
            rec_url.get("alive") if (rec_url and "alive" in rec_url) else
            (rec_host.get("alive") if (rec_host and "alive" in rec_host) else None)
        )
        status = "up" if alive is True else ("down" if alive is False else "-")

        filtered_rows.append({
            "url": s,
            "open_url": final,
            "status": status,
            "code": code_i,
            "size": _fmt_size_human(size_i),
            "title": title,
            "content_type": ctype,
            "last_probe": _fmt_last_probe(lastp),
            "host": host,
            "scheme": scheme,
            # NEW: echo method ke row (optional untuk kolom di UI)
            "method": method_val_u or None,
        })

    # ---------- paginate ----------
    total       = len(filtered_rows)
    total_pages = max(1, (total + page_size - 1) // page_size)
    if page > total_pages: page = total_pages
    start = (page - 1) * page_size
    end   = start + page_size
    rows  = filtered_rows[start:end]

    stats_pack = _gather_stats(scope)
    stats = stats_pack["stats"]
    stats_map = {row["module"]: row for row in stats}

    ctx = {
        "request": request,
        "scope": scope,
        "module": mod,
        "rows": rows,

        # filters echo
        "q": q,
        "http_class": http_class or "(any)",
        "codes": codes_str,
        "ctype": ctype_sub,
        "min_size": min_size,
        "max_size": max_size,
        "scheme": scheme_f or "(any)",
        "host": host_f,
        # NEW: kirim ke template/pager
        "method_filter": method_filter or "(any)",

        # dropdown options for Subdomain filter
        "host_options": host_options,

        # pager context
        "page": page,
        "page_size": page_size,
        "limit": page_size,
        "total": total,
        "total_pages": total_pages,
        "pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "page_url": page_url,

        # tabs
        "stats": stats,
        "stats_map": stats_map,
        "module_name": mod,
        
        "discovery_host_options": discovery_host_options,
        "wordlists": wordlists,
    }
    return templates.TemplateResponse("module_generic.html", ctx)


# === CLI Console ============================================================

def _python_exe() -> str:
    ve = os.environ.get("VIRTUAL_ENV")
    if ve:
        p3 = Path(ve) / "bin" / "python3"
        p  = Path(ve) / "bin" / "python"
        if p3.exists():
            return str(p3)
        if p.exists():
            return str(p)
    return which("python3") or which("python") or "python3"


def _tool_cmd(tool: str, scope: str, outputs_root: Path, *, module: str | None = None, host: str | None = None, wordlists: str | None = None,) -> list[str]:
    """
    Build command to run in the repo root.
    - gau / waymore
    - build
    - probe_subdomains
    - probe_module (with module=...)
    - subfinder / amass / findomain  (passive subdomain collectors)
    """
    py_exe = _python_exe()
    out_dir = outputs_root / scope

    if tool == "gau":
        return ["gau", "--verbose", scope]

    if tool == "waymore":
        return ["waymore", "-i", scope, "-o", "-"]

    if tool == "build":
        return [
            py_exe, "-m", "ReconLens",
            "--scope", scope,
            "--input", str(out_dir / "urls.txt"),
            "--out",   str(out_dir),
        ]

    if tool == "probe_subdomains":
        return [
            py_exe, "-m", "ReconLens.tools.probe_subdomains",
            "--scope", scope,
            "--input", str(out_dir / "subdomains.txt"),
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

        candidates = out_dir / f"{mod}_candidates.txt"
        fallback   = out_dir / f"{mod}.txt"
        if candidates.exists():
            input_file = candidates
        elif fallback.exists():
            input_file = fallback
        else:
            input_file = candidates  # biar errornya jelas di CLI

        ua = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/124.0 Safari/537.36")

        default_mode = "GET"  # untuk sebagian besar modul

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
    
    if tool == "dirsearch":
        if not host:
            raise ValueError("dirsearch requires host")
        # stdout cukup kaya; kita tetap regex URL di _run_job
        # NB: jalankan dengan target full origin; kamu bisa ganti wordlist/opts sesuai preferensi
        return [
            "dirsearch",
            "-u", f"https://{host}",
            "-w", f"{get_wordlists_dir()}/{wordlists}",
            "--format=simple",
            "--full-url",
            "--crawl", "0",
            "--random-agent",
            "--quiet",
        ]
    if tool == "probe_paths":
        if not host:
            raise ValueError("dirsearch requires host")
        # stdout cukup kaya; kita tetap regex URL di _run_job
        # NB: jalankan dengan target full origin; kamu bisa ganti wordlist/opts sesuai preferensi
        return [
            "dirsearch",
            "-u", f"https://{host}",
            "--format=simple",
            "--full-url",
            "--crawl", "0",
            "--random-agent",
            "--quiet",
        ]
    # --- passive subdomain collectors ---
    if tool == "subfinder":
        # output baris hostname; akan di-merge ke subdomains.txt
        return ["subfinder", "-d", scope, "-all", "-silent"]
    if tool == "amass":
        # amass enum passive, keluaran mix → kita capture & normalisasi ke hostnames
        return ["amass", "enum", "-passive", "-d", scope]
    if tool == "findomain":
        # findomain (butuh terinstall). STDOUT hostname
        return ["findomain", "--target", scope, "--quiet"]

    raise ValueError(f"unknown tool: {tool}")


async def _run_job(scope: str, tool: str, out_dir: Path, job_id: str):
    job = JOBS[job_id]

    # --- prepare dirs --------------------------------------------------------
    out_dir.mkdir(parents=True, exist_ok=True)
    jobs_dir = out_dir / "__jobs__"
    jobs_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = out_dir / "raw"
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
        outputs_root = out_dir.parent        # .../ReconLens/outputs
        package_root = outputs_root.parent   # .../ReconLens
        repo_root    = package_root.parent   # .../url_parser_real_world

        module = job.get("module")
        host   = job.get("host")
        wordlists   = job.get("wordlists")
        cmd = _tool_cmd(tool, scope, outputs_root, module=module, host=host, wordlists=wordlists)

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

        # --------- SINGLE STDOUT READER ---------
        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.decode("utf-8", "ignore").rstrip("\n")

            # write full to log & raw
            log_f.write(line + "\n"); log_f.flush()
            raw_f.write(line + "\n"); raw_f.flush()

            # --- capture heuristics ---
            if tool == "dirsearch":
                parsed = _parse_dirsearch_line(line)
                if parsed:
                    urls_tmp_f.write(parsed["url"] + "\n"); urls_tmp_f.flush()
                    captured += 1
                    # update enrich per-URL
                    _update_url_enrich_from_dirsearch(
                        outputs_root, scope, parsed["url"], parsed["code"], parsed["size"]
                    )
            elif "://" in line:
                urls_tmp_f.write(line + "\n"); urls_tmp_f.flush()
                captured += 1
            else:
                if tool in ("subfinder", "amass", "findomain"):
                    if line.strip():
                        urls_tmp_f.write(line + "\n"); urls_tmp_f.flush()
                        captured += 1

            # (opsional) progress events
            if line.startswith("TOTAL ") or line.startswith("PROGRESS "):
                await q.put(f"event: progress\ndata: {line}\n\n")

            # kirim ke UI (truncate biar rapih)
            await q.put(line[:200] + "\n")

        rc = await proc.wait()
        await q.put(f"\n[exit] code={rc}\n")
        job["exit_code"] = rc

        # close tmp holders before post-processing
        urls_tmp_f.close()
        raw_f.close()

        # Post-merge behavior
        if tool in ("gau", "waymore"):
            target = out_dir / "urls.txt"
            before = _read_text_lines(target)
            _merge_urls(target, tmp_urls)
            after  = _read_text_lines(target)
            added_unique = max(0, after - before)
            await q.put(f"[summary] captured={captured}  unique_added={added_unique}  total_now={after}\n")
            await q.put(f"[summary] merged → {target}\n")

        elif tool in ("subfinder", "amass", "findomain"):
            target = out_dir / "subdomains.txt"
            before = _read_text_lines(target)
            _merge_hostnames(target, tmp_urls)
            after  = _read_text_lines(target)
            added = max(0, after - before)
            _update_last_scan(scope, tool)
            await q.put(f"[summary] captured={captured}  unique_added={added}  total_now={after}\n")
            await q.put(f"[summary] merged → {target}\n")

        elif tool == "build":
            _update_last_scan(scope, "build")
            await q.put(f"[summary] rebuild done. outputs → {out_dir}\n")

        elif tool == "probe_subdomains":
            _update_last_scan(scope, "subdomains")
            await q.put(f"[summary] probe (subdomains) done. outputs → {out_dir}\n")

        elif tool == "probe_module":
            module_key = (job.get("module") or "probe").lower()
            _update_last_scan(scope, module_key)
            if module:
                await q.put(f"[summary] probe (module={module}) done. outputs → {out_dir}\n")
            else:
                await q.put(f"[summary] probe done. outputs → {out_dir}\n")

        elif tool == "dirsearch":
            host = (job.get("host") or "").strip().lower()

            # 1) simpan per-host: outputs/<scope>/dirsearch/<host>/
            host_dir = out_dir / "dirsearch" / host
            host_dir.mkdir(parents=True, exist_ok=True)
            job_report = host_dir / f"{job_id}.txt"
            try:
                os.replace(tmp_urls, job_report)
            except Exception:
                pass

            # 2) merge semua temuan host ini → found.txt
            found = host_dir / "found.txt"
            before_host = _read_text_lines(found)
            _merge_urls(found, job_report)
            after_host  = _read_text_lines(found)

            # 3) merge seluruh temuan → dirsearch.txt
            agg = out_dir / "dirsearch.txt"
            before_agg = _read_text_lines(agg)
            _merge_urls(agg, job_report)
            after_agg  = _read_text_lines(agg)

            # 4) update penanda waktu
            _update_dirsearch_last(out_dir, host)
            _update_last_scan(scope, "dirsearch")

            await q.put(
                f"[summary] captured={captured}  unique_added_host={max(0, after_host-before_host)}  "
                f"host_total={after_host}\n"
            )
            await q.put(
                f"[summary] merged (aggregate) → {agg}  unique_added_agg={max(0, after_agg-before_agg)}  "
                f"agg_total={after_agg}\n"
            )
        elif tool == "probe_paths":
            host = (job.get("host") or "").strip().lower()

            # 1) simpan per-host: outputs/<scope>/dirsearch/<host>/
            host_dir = out_dir / "dirsearch" / host
            host_dir.mkdir(parents=True, exist_ok=True)
            job_report = host_dir / f"{job_id}.txt"
            try:
                os.replace(tmp_urls, job_report)
            except Exception:
                pass

            # 2) merge semua temuan host ini → found.txt
            found = host_dir / "found.txt"
            before_host = _read_text_lines(found)
            _merge_urls(found, job_report)
            after_host  = _read_text_lines(found)

            # 3) merge seluruh temuan → dirsearch.txt
            agg = out_dir / "dirsearch.txt"
            before_agg = _read_text_lines(agg)
            _merge_urls(agg, job_report)
            after_agg  = _read_text_lines(agg)

            # 4) update penanda waktu
            _update_dirsearch_last(out_dir, host)
            _update_last_scan(scope, "dirsearch")

            await q.put(
                f"[summary] captured={captured}  unique_added_host={max(0, after_host-before_host)}  "
                f"host_total={after_host}\n"
            )
            await q.put(
                f"[summary] merged (aggregate) → {agg}  unique_added_agg={max(0, after_agg-before_agg)}  "
                f"agg_total={after_agg}\n"
            )
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


# === Job endpoints ===========================================================

def _new_job(scope: str, tool: str, module: Optional[str] = None, host: Optional[str] = None, wordlists: Optional[str] = None) -> str:
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
        "wordlists":wordlists
    }
    return jid


@router.get("/{scope}/collect/{tool}", response_class=HTMLResponse)
async def collect_console(request: Request, scope: str, tool: str, module: Optional[str] = None):
    out_dir = OUTPUTS_DIR / scope
    urls_txt = str(out_dir / "urls.txt") if (out_dir / "urls.txt").exists() else ""
    
    # untuk dirsearch
    wl_name = request.query_params.get("wordlist") or ""
    wl_path = resolve_wordlist(wl_name)
    if wl_path is None:
        wl_name = "small.txt"
    # last_scans untuk tampilan hint
    meta = _safe_json_load(out_dir / "meta.json")
    last_scans = meta.get("last_scans", {})
    host = request.query_params.get("host") or ""
    return TEMPLATES.TemplateResponse("collect_console.html", {
        "request": request,
        "scope": scope,
        "tool": tool,
        "module": module,
        "urls_txt": urls_txt,
        "last_scans": last_scans,
        "host": host,
        "wordlist":wl_name,
    })


@router.post("/{scope}/collect/{tool}/start")
async def collect_start(scope: str, tool: str, request: Request):
    # ambil module dari query (?module=...)
    module = request.query_params.get("module")
    host   = request.query_params.get("host")  # (khusus dirsearch)
    
    # khusus dirsearch → validasi host
    if tool == "dirsearch":
        raw_host = request.query_params.get("host", "").strip()
        wl_name = request.query_params.get("wordlist") or ""
        wl_path = resolve_wordlist(wl_name)
        if wl_path is None:
            wl_name = "small.txt"
            
        if not raw_host:
            return JSONResponse({"ok": False, "error": "host param is required for dirsearch"}, status_code=400)
        host = _normalize_host(raw_host)
        if not _host_in_scope(host, scope):
            return JSONResponse({"ok": False, "error": "host not in scope"}, status_code=400)

        jid = _new_job(scope, tool, module=None, host=host, wordlists=wl_name)
        out_dir = OUTPUTS_DIR / scope
        asyncio.create_task(_run_job(scope, tool, out_dir, jid))
        return JSONResponse({"ok": True, "job_id": jid})
        
    jid = _new_job(scope, tool, module=module)
    JOBS[jid]["host"] = host
    
    out_dir = OUTPUTS_DIR / scope
    # jalankan
    asyncio.create_task(_run_job(scope, tool, out_dir, jid))
    return JSONResponse({"ok": True, "job_id": jid})


@router.post("/{scope}/collect/{tool}/cancel")
async def collect_cancel(scope: str, tool: str, job: str):
    info = JOBS.get(job)
    if not info:
        return JSONResponse({"ok": False, "error": "job not found"})
    proc = info.get("proc")
    if proc and proc.returncode is None:
        try:
            proc.send_signal(signal.SIGINT)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass
    return JSONResponse({"ok": True})


@router.get("/{scope}/collect/{tool}/stream")
async def collect_stream(scope: str, tool: str, job: str):
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
            # SSE basic (plain data lines). Kita sudah embed "event: status" manual saat perlu.
            if item.startswith("event:"):
                # sudah SSE format penuh
                yield item
            else:
                for line in item.splitlines():
                    yield f"data: {line}\n"
                yield "\n"

    return StreamingResponse(eventgen(), media_type="text/event-stream")


# === Assets / Downloads =====================================================

@router.get("/{scope}/download/{fname}")
async def download(scope: str, fname: str):
    p = OUTPUTS_DIR / scope / fname
    if not p.exists():
        raise HTTPException(404, "file not found")
    return Response(
        content=p.read_bytes(),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{p.name}"'},
    )

# --- Convenience aliases ----------------------------------------------------

@router.get("/{scope}/probe/module/{module}", response_class=HTMLResponse)
async def probe_module_console_alias(request: Request, scope: str, module: str):
    # Reuse the collect console UI
    return await collect_console(request, scope=scope, tool="probe_module", module=module)

@router.post("/{scope}/probe/module/{module}/start")
async def probe_module_start_alias(scope: str, module: str, request: Request):
    # Reuse the collect start handler with ?module=...
    # Build a Request object with the query param present
    # (FastAPI already gives us `request`, but we can just pass module to _new_job)
    jid = _new_job(scope, "probe_module", module=module)
    out_dir = OUTPUTS_DIR / scope
    asyncio.create_task(_run_job(scope, "probe_module", out_dir, jid))
    return JSONResponse({"ok": True, "job_id": jid})
