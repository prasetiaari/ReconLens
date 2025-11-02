from __future__ import annotations
import math
from pathlib import Path
from fastapi import APIRouter, Request, HTTPException
from app.core.settings import get_settings
from app.core.templates import get_templates
from app.core.fs import iter_lines
from datetime import datetime, timezone
from typing import Any
from fastapi.responses import HTMLResponse, Response
import json

from app.services.enrich_subdomains import get_probe_map_cached as load_enrich
router = APIRouter()

def _decorate_enrich_for_hosts(enrich: dict, hosts: list[str]) -> None:
    def _fmt_last_probe(val):
        if not val: return "-"
        try:
            if isinstance(val, (int, float)):
                dt = datetime.fromtimestamp(int(val), tz=timezone.utc)
            else:
                dt = datetime.fromisoformat(str(val))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(val)

    def _fmt_kb(n):
        try:
            if n is None: return None, "-"
            kb = float(n) / 1024.0
            return kb, f"{kb:.1f} KB"
        except Exception:
            return None, "-"

    for host in hosts:
        rec = enrich.get(host)
        if not rec:
            continue
        rec["last_probe_fmt"] = _fmt_last_probe(rec.get("last_probe"))
        kb_val, kb_str = _fmt_kb(rec.get("size"))
        rec["size_kb"]  = kb_val
        rec["size_fmt"] = kb_str


def _host_in_scope(host: str, scope: str) -> bool:
    host = (host or "").lower()
    scope = (scope or "").lower()
    return host.endswith("." + scope) or host == scope
    
def _fmt_ts(ts: float) -> str:
    try:
        # ISO pendek sebagai fallback; view bisa render 'timeago' sendiri
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "—"
def _fmt_iso_short(val: str | None) -> str:
    """
    Terima ISO string (dengan / tanpa 'Z' / offset), kembalikan 'YYYY-MM-DD HH:MM'.
    """
    if not val:
        return "-"
    try:
        s = str(val)
        if s.endswith("Z"):
            s = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        # tampilkan singkat; kalau mau localize tinggal ganti di sini
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "-"
        
def load_dirsearch_last(outputs_dir: Path, scope: str) -> dict[str, str]:
    """
    Baca outputs/<scope>/__cache/dirsearch_last.json -> {host: ISO8601 string}
    """
    p = outputs_dir / scope / "__cache" / "dirsearch_last.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
def load_dirsearch_counts(outputs_dir: Path, scope: str) -> dict[str, int]:
    """
    Hitung jumlah baris (URL) hasil dirsearch per host:
    outputs/<scope>/dirsearch/<host>/found.txt -> {host: lines}
    """
    base = outputs_dir / scope / "dirsearch"
    out: dict[str, int] = {}
    if not base.exists():
        return out
    for d in base.iterdir():
        if not d.is_dir():
            continue
        host = d.name
        f = d / "found.txt"
        if f.exists():
            try:
                with f.open("r", encoding="utf-8", errors="ignore") as fh:
                    out[host] = sum(1 for _ in fh)
            except Exception:
                out[host] = 0
    return out
    
def build_last_scans(outputs_dir: Path, scope: str, tools=("subfinder","amass","findomain","bruteforce")) -> dict:
    """
    Cari file di outputs/<scope>/raw/<tool>-*.urls, pakai mtime terbaru sebagai last scan.
    """
    raw_dir = outputs_dir / scope / "raw"
    result = {}
    try:
        for t in tools:
            latest_ts = None
            if raw_dir.exists():
                for p in raw_dir.glob(f"{t}-*.urls"):
                    try:
                        mt = p.stat().st_mtime
                        if (latest_ts is None) or (mt > latest_ts):
                            latest_ts = mt
                    except Exception:
                        pass
            result[t] = _fmt_ts(latest_ts) if latest_ts else "—"
    except Exception:
        # jangan gagal halaman hanya karena ini
        for t in tools:
            result[t] = "—"
    return result
    
def _coerce_ts(value: Any) -> datetime | None:
    """
    Terima epoch int/str, atau ISO string (dengan/ tanpa 'Z'), kembalikan datetime UTC.
    """
    if value is None:
        return None
    # epoch number
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(int(value), tz=timezone.utc)
        except Exception:
            return None
    # string
    if isinstance(value, str):
        s = value.strip()
        # epoch in string
        if s.isdigit():
            try:
                return datetime.fromtimestamp(int(s), tz=timezone.utc)
            except Exception:
                return None
        # ISO
        try:
            if s.endswith("Z"):
                s = s.replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None
    return None
def _time_ago_from_any(value: Any) -> str:
    dt = _coerce_ts(value)
    if not dt:
        return "-"
    now = datetime.now(timezone.utc)
    delta = (now - dt).total_seconds()
    if delta < 1:
        return "now"
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta//60)}m ago"
    if delta < 86400:
        return f"{int(delta//3600)}h ago"
    return f"{int(delta//86400)}d ago"
    
def _parse_iso(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        # dukung ...Z (UTC) dan offset-aware ISO
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def _time_ago(ts: str) -> str:
    dt = _parse_iso(ts)
    if not dt:
        return "-"
    now = datetime.now(timezone.utc)
    if not dt.tzinfo:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = (now - dt).total_seconds()
    if delta < 1:
        return "now"
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // 86400)}d ago"

def _decorate_last_probe(enrich: dict[str, dict], hosts: list[str]) -> None:
    """
    Mutasi in-memory: set rec['last_probe'] sebagai string 'ago'.
    Ambil sumber dari rec['last_probe'] (epoch/ISO) atau fallback rec['ts'].
    """
    for h in hosts:
        rec = enrich.get(h)
        if not rec:
            continue
        raw = rec.get("last_probe")
        if raw is None:
            raw = rec.get("ts")
        rec["last_probe"] = _time_ago_from_any(raw)
            
def _alive_flag(req: Request) -> bool:
    v = (req.query_params.get("alive") or "").lower()
    return v in ("1", "true", "on", "yes")

def _resolve_subdomains_file(outputs_dir: Path, scope: str, modules_conf) -> Path:
    # modules_conf bisa dict atau list; safe-get
    filename = "subdomains.txt"
    if isinstance(modules_conf, dict):
        mod = modules_conf.get("subdomains")
        if isinstance(mod, dict):
            filename = mod.get("file", filename)
    return outputs_dir / scope / filename

def _iter_hosts_filtered(path: Path, q: str, enrich: dict[str, dict], alive_only: bool):
    if not path.exists():
        return
    for host in iter_lines(path):
        if q and q not in host:
            continue
        if alive_only:
            rec = enrich.get(host)
            if not (rec and rec.get("alive")):
                continue
        yield host

def _paginate_iter(it, page: int, page_size: int):
    start = max(0, (page - 1) * page_size)
    end = start + page_size
    rows, idx = [], 0
    for host in it:
        if idx >= start and idx < end:
            rows.append(host)
        idx += 1
    total = idx
    total_pages = max(1, math.ceil(total / max(1, page_size)))
    has_prev = page > 1
    has_next = page < total_pages
    return rows, total, total_pages, has_prev, has_next

@router.get("/targets/{scope}/subdomains/ip_clusters", response_class=HTMLResponse)
async def subdomains_ip_clusters(scope: str, request: Request):
    settings = get_settings(request)
    templates = get_templates(request)

    # endpoint JSON untuk graph (yang sudah kamu buat di services/…)
    data_url = f"/targets/{scope}/subdomains/ip_clusters.json"

    ctx = {
        "request": request,
        "scope": scope,
        "data_url": data_url,
        "back_url": f"/targets/{scope}/subdomains",
    }
    return templates.TemplateResponse("subdomains_ip_clusters.html", ctx)
    
@router.get("/targets/{scope}/subdomains")
async def subdomains_page(scope: str, request: Request):
    settings  = get_settings(request)
    templates = get_templates(request)

    q         = (request.query_params.get("q") or "").strip()
    page      = int(request.query_params.get("page") or 1)
    page_size = int(request.query_params.get("page_size") or 100)
    alive     = _alive_flag(request)

    outputs_dir = Path(settings.OUTPUTS_DIR)
    page_url    = f"/targets/{scope}/subdomains"

    # file subdomain hasil engine baru: outputs/<scope>/subdomains.txt
    sub_file = outputs_dir / scope / "subdomains.txt"
    enrich   = load_enrich(outputs_dir, scope) or {}

    # NEW: dirsearch last map (formatted)
    dir_last_raw = load_dirsearch_last(outputs_dir, scope)
    dir_last = {h: _fmt_iso_short(ts) for h, ts in dir_last_raw.items()}
    dir_counts = load_dirsearch_counts(outputs_dir, scope)
    
    hosts: list[str] = []
    if sub_file.exists():
        with sub_file.open("r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                h = ln.strip()
                if not h or h.startswith("#"):
                    continue
                hosts.append(h)

    # filter q
    if q:
        ql = q.lower()
        hosts = [h for h in hosts if ql in h.lower()]

    # filter alive (pakai enrich)
    if alive:
        hosts = [h for h in hosts if (enrich.get(h) or {}).get("alive")]

    total = len(hosts)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(page, total_pages))
    start = (page - 1) * page_size
    end   = start + page_size
    rows  = hosts[start:end]               # <<-- penting: list[str], bukan dict

    # opsional: debug ke console
    #print(f"[debug] subdomains_page: file={sub_file} total_hosts={total} page={page}/{total_pages}")
    _decorate_enrich_for_hosts(enrich, rows)
    last_scans = build_last_scans(settings.OUTPUTS_DIR, scope)
    from .targets.helpers import gather_stats  # import di dalam fungsi
    stats_pack = gather_stats(scope)
    stats = stats_pack["stats"]
    stats_map = {row["module"]: row for row in stats}
    ctx = {
        "request": request,
        "scope": scope,
        "page_url": page_url,
        "q": q,
        "page": page,
        "page_size": page_size,
        "alive": alive,
        "rows": rows,
        "total": total,
        "last_scans": last_scans,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "enrich": enrich,
        "stats": stats,
        "stats_map": stats_map,
        "module_name": "subdomains",
        "dirsearch_last": dir_last,
        "dirsearch_counts": dir_counts,
    }
    return templates.TemplateResponse("subdomains.html", ctx)

# OPTIONAL: kalau kamu masih butuh endpoint rows-only
async def subdomains_rows(scope: str, request: Request):
    settings  = get_settings(request)
    templates = get_templates(request)

    q         = request.query_params.get("q") or ""
    page      = int(request.query_params.get("page") or 1)
    page_size = int(request.query_params.get("page_size") or 100)
    alive     = _alive_flag(request)

    outputs_dir = Path(settings.OUTPUTS_DIR)
    page_url    = f"/targets/{scope}/subdomains"

    sub_file = _resolve_subdomains_file(outputs_dir, scope, settings.MODULES)
    enrich   = load_enrich(outputs_dir, scope) or {}
    
    # NEW
    dir_last_raw = load_dirsearch_last(outputs_dir, scope)
    dir_last = {h: _fmt_local_short(ts) for h, ts in dir_last_raw.items()}
    dir_counts = load_dirsearch_counts(outputs_dir, scope)
    
    it = _iter_hosts_filtered(sub_file, q, enrich, alive_only=alive)
    rows, total, total_pages, has_prev, has_next = _paginate_iter(it, page, page_size)

    # ---- inject dekorasi ke setiap record enrich yang dipakai di tabel ----
    from datetime import datetime, timezone

    def _fmt_last_probe(val):
        if not val:
            return "-"
        try:
            # dukung epoch int/float atau ISO string
            if isinstance(val, (int, float)):
                dt = datetime.fromtimestamp(int(val), tz=timezone.utc)
            else:
                dt = datetime.fromisoformat(str(val))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            # samakan gaya dengan modul lain (YYYY-MM-DD HH:MM:SS)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(val)

    # hiasan: size → KB (angka dan string) biar bisa dipakai bebas di template
    def _fmt_kb(n):
        try:
            if n is None:
                return None, "-"
            kb = float(n) / 1024.0
            return kb, f"{kb:.1f} KB"
        except Exception:
            return None, "-"

    # hanya dekorasi host yang tampil di halaman (hemat)
    for host in rows:
        rec = enrich.get(host)
        if not rec:
            continue
        # last_probe yang sudah diformat
        rec["last_probe_fmt"] = _fmt_last_probe(rec.get("last_probe"))
        # size yang sudah diubah ke KB
        kb_val, kb_str = _fmt_kb(rec.get("size"))
        rec["size_kb"]  = kb_val     # angka (mis. 6.0)
        rec["size_fmt"] = kb_str     # string (mis. "6.0 KB")

    # (opsional) tetap panggil util existing kalau kamu masih pakai di tempat lain
    # _decorate_last_probe(enrich, rows)

    ctx = {
        "request": request,
        "scope": scope,
        "page_url": page_url,
        "q": q,
        "page": page,
        "page_size": page_size,
        "alive": alive,
        "rows": rows,                     # list of hosts
        "total": total,
        "total_pages": total_pages,
        "has_prev": has_prev,
        "has_next": has_next,
        "enrich": enrich,                 # sekarang tiap rec punya last_probe_fmt & size_fmt
        "dirsearch_last": dir_last,
        "dirsearch_counts": dir_counts,
    }
    return templates.TemplateResponse("subdomains.html", ctx)

@router.get("/targets/{scope}/dirsearch/{host}", response_class=HTMLResponse)
async def dirsearch_view(scope: str, host: str, request: Request):
    settings  = get_settings(request)
    templates = get_templates(request)

    if ("/" in host) or (".." in host) or not _host_in_scope(host, scope):
        raise HTTPException(400, "invalid host")

    base   = Path(settings.OUTPUTS_DIR) / scope / "dirsearch" / host
    fpath  = base / "found.txt"
    if not fpath.exists():
        raise HTTPException(404, "no dirsearch result for this host")

    q         = (request.query_params.get("q") or "").strip()
    page      = int(request.query_params.get("page") or 1)
    page_size = int(request.query_params.get("page_size") or 50)
    page_url  = f"/targets/{scope}/dirsearch/{host}"

    # load & filter
    rows_all: list[str] = []
    with fpath.open("r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            s = ln.strip()
            if not s:
                continue
            if q and q.lower() not in s.lower():
                continue
            rows_all.append(s)

    total       = len(rows_all)
    total_pages = max(1, (total + page_size - 1) // page_size)
    if page > total_pages: page = total_pages
    start, end = (page - 1) * page_size, (page - 1) * page_size + page_size
    rows = rows_all[start:end]

    # Reuse module_generic.html
    return templates.TemplateResponse("module_generic.html", {
        "request": request,
        "scope": scope,
        "module": f"dirsearch:{host}",
        "rows": rows,
        "q": q,
        "page": page,
        "page_size": page_size,
        "limit": page_size,
        "total": total,
        "total_pages": total_pages,
        "pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "page_url": page_url,
    })

@router.get("/targets/{scope}/dirsearch/{host}/download")
async def dirsearch_download(scope: str, host: str, request: Request):
    settings = get_settings(request)
    if ("/" in host) or (".." in host) or not _host_in_scope(host, scope):
        raise HTTPException(400, "invalid host")
    fpath = Path(settings.OUTPUTS_DIR) / scope / "dirsearch" / host / "found.txt"
    if not fpath.exists():
        raise HTTPException(404, "file not found")
    return Response(
        content=fpath.read_bytes(),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{host}-dirsearch.txt"'},
    )
