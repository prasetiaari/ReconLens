from __future__ import annotations

from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse, RedirectResponse

from app.deps import get_settings, get_templates
from app.core.modules import MODULE_FILES  # mapping: module -> filename

import json
from datetime import datetime, timezone

router = APIRouter(prefix="/targets")


# =========================
# Canonicalization & lookup helpers
# =========================
def _canon_url(u: str) -> str:
    """
    Canonicalize URL supaya cocok saat lookup index:
    - normalisasi scheme & host ke lowercase
    - hapus default port (:80, :443)
    - hilangkan fragment
    """
    try:
        p = urlparse(u.strip())
        scheme = (p.scheme or "http").lower()
        netloc = p.netloc.lower()

        # hapus default port
        if ":" in netloc:
            host, port = netloc.split(":", 1)
            if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                netloc = host

        fragless = p._replace(netloc=netloc, scheme=scheme, fragment="")
        return urlunparse(fragless)
    except Exception:
        return u.strip()


def _lookup_enrich(idx: dict, url: str) -> dict:
    """Coba beberapa varian URL agar match dengan index."""
    if url in idx:
        return idx[url]
    cu = _canon_url(url)
    if cu in idx:
        return idx[cu]
    try:
        p = urlparse(url)
        alt = url.replace("http://", "https://", 1) if p.scheme == "http" else url.replace("https://", "http://", 1)
        if alt in idx:
            return idx[alt]
        calt = _canon_url(alt)
        if calt in idx:
            return idx[calt]
    except Exception:
        pass
    return {}


def _iso_from_epoch(val):
    try:
        return datetime.fromtimestamp(int(val), tz=timezone.utc).isoformat()
    except Exception:
        return None


# =========================
# Probe index loader (service-first, fallback reader)
# =========================
def _load_probe_index(scope: str, outputs_dir) -> dict[str, dict]:
    """
    Kembalikan index: url -> {code, status, size, ctype, title, ts}
    Prioritas:
      1) pakai service/url_cache.py yang sudah ada (berbagai kemungkinan API umum)
      2) fallback: baca __cache/url_probe.ndjson langsung
    """
    # 1) coba beberapa API umum yang mungkin sudah ada di project kamu
    try:
        from app.services import url_cache as uc

        # a. singleton object + .get(scope, cache_dir)
        if hasattr(uc, "url_probe_cache") and hasattr(uc.url_probe_cache, "get"):
            cache_dir = outputs_dir / scope / "__cache"
            idx = uc.url_probe_cache.get(scope, cache_dir)
            # tambahkan canonical view tanpa mengubah aslinya
            if isinstance(idx, dict) and idx:
                extra = {}
                for u, rec in idx.items():
                    cu = _canon_url(u)
                    if cu not in idx:
                        extra[cu] = rec
                if extra:
                    idx.update(extra)
            return idx

        # b. fungsi langsung
        for fname in ("get_url_index", "get_probe_index", "get_url_probe_index", "load_url_index"):
            if hasattr(uc, fname):
                idx = getattr(uc, fname)(scope)
                if isinstance(idx, dict) and idx:
                    extra = {}
                    for u, rec in idx.items():
                        cu = _canon_url(u)
                        if cu not in idx:
                            extra[cu] = rec
                    if extra:
                        idx.update(extra)
                return idx

    except Exception:
        pass  # kita akan fallback

    # 2) fallback reader
    idx: dict[str, dict] = {}
    nd = outputs_dir / scope / "__cache" / "url_probe.ndjson"
    if not nd.exists():
        return idx

    with nd.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue

            url = None
            payload = None

            # FORMAT A: {"url": "...", "status_code": 200, ...}
            if isinstance(rec, dict) and "url" in rec:
                url = rec.get("url")
                payload = rec

            # FORMAT B: {"http://host/path": { ...fields... }}
            elif isinstance(rec, dict) and len(rec) == 1:
                url, payload = next(iter(rec.items()))

            if not url or not isinstance(payload, dict):
                continue

            code = payload.get("status_code")
            if code is None:
                code = payload.get("code")

            # derive status (prioritas 'alive', fallback dari code)
            alive = payload.get("alive")
            if isinstance(alive, bool):
                status = "up" if alive else "down"
            elif isinstance(code, int):
                if   200 <= code <= 299: status = "up"
                elif 300 <= code <= 399: status = "redirect"
                elif 400 <= code <= 499: status = "client"
                elif 500 <= code <= 599: status = "server"
                else: status = "other"
            else:
                status = "-"

            # size & ctype
            size  = payload.get("content_length")
            if size is None:
                size = payload.get("size")
            ctype = payload.get("content_type") or payload.get("ctype")

            # title
            title = payload.get("title") or ""

            # timestamp → ISO (timeago-friendly)
            ts = payload.get("last_probe") or payload.get("@ts") or payload.get("ts") or payload.get("time")
            iso_ts = _iso_from_epoch(ts) if isinstance(ts, (int, float, str)) else None

            idx[url] = {
                "code": code,
                "status": status,
                "size": size,
                "ctype": ctype,
                "title": title,
                "ts": iso_ts or "-",   # kosongkan kalau gagal parse
            }

    # tambahkan index canonical (http/https, :80/:443)
    extra = {}
    for u, rec in idx.items():
        cu = _canon_url(u)
        if cu not in idx:
            extra[cu] = rec
    if extra:
        idx.update(extra)
    return idx


# =========================
# Misc helpers
# =========================
def _humansize(n):
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


def _parse_codes(codes: str | None) -> set[int]:
    s = set()
    if not codes:
        return s
    for t in codes.split(","):
        t = t.strip()
        if not t:
            continue
        try:
            s.add(int(t))
        except:
            pass
    return s


def _match_http_class(code: int | None, klass: str | None) -> bool:
    if not klass or klass in ("", "any", "(any)"):
        return True
    if code is None:
        return False
    k = klass.lower()
    if k == "2xx":
        return 200 <= code <= 299
    if k == "3xx":
        return 300 <= code <= 399
    if k == "4xx":
        return 400 <= code <= 499
    if k == "5xx":
        return 500 <= code <= 599
    return True


def _build_qs_preserve(request: Request, *, pages: int, limit: int, page: int):
    """
    Build helpers that ALWAYS preserve current filters from request.query_params,
    only replacing the 'page' (and normalizing page_size).
    """
    # Take the current query params as dict[str, str]
    current_qs = dict(request.query_params.multi_items())
    # Remove duplicates by keeping last occurrence
    tmp = {}
    for k, v in current_qs.items():
        tmp[k] = v
    current_qs = tmp

    # Normalize keys we control
    current_qs.pop("offset", None)          # not used anymore
    current_qs["page_size"] = str(limit)    # reflect normalized limit

    def qs_for_page(p: int) -> str:
        p = max(1, min(p, pages))
        merged = {**current_qs, "page": str(p)}
        # drop empty values to keep URL tidy
        merged = {k: v for k, v in merged.items() if v not in (None, "", [])}
        return "?" + urlencode(merged)

    qs_prev = qs_for_page(page - 1) if page > 1 else None
    qs_next = qs_for_page(page + 1) if page < pages else None
    apply_qs = qs_for_page(1)               # apply filters -> go to page 1
    reset_qs = request.url.path             # reset to base path (no query)

    return qs_for_page, qs_prev, qs_next, apply_qs, reset_qs


# =========================
# OLD: download raw by filename
# =========================
@router.get("/{scope}/download/{filename}", response_class=PlainTextResponse)
def download(scope: str, filename: str, request: Request):
    settings = get_settings(request)
    fp = (settings.OUTPUTS_DIR / scope / filename).resolve()
    if settings.OUTPUTS_DIR.resolve() not in fp.parents:
        return PlainTextResponse("Invalid path", status_code=400)
    if not fp.exists():
        return PlainTextResponse("Not found", status_code=404)
    text = fp.read_text(encoding="utf-8", errors="ignore")
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return PlainTextResponse(text, headers=headers)


# =========================
# NEW: generic module (list.json, download, UI)
# =========================
@router.get("/{scope}/module/{module}/list.json")
def list_module(
    scope: str,
    module: str,
    # simple filters supported by raw line file
    q: str | None = None,
    host: str | None = None,
    param: str | None = None,
    offset: int = 0,
    limit: int = Query(50, le=1000),
    request: Request = None,  # tidak dipakai di sini, biar konsisten signature
):
    settings = get_settings(request)
    filename = MODULE_FILES.get(module.upper())
    if not filename:
        return {"total": 0, "items": []}

    path = settings.OUTPUTS_DIR / scope / filename
    # versi list.json tetap minimal (tanpa enrich) biar ringan
    total, items = 0, []
    if path.exists():
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                url = line.strip()
                if not url:
                    continue
                if q and q not in url:
                    continue
                if host and host not in url:
                    continue
                if param and (f"{param}=" not in url):
                    continue
                if total >= offset and len(items) < limit:
                    items.append(url)
                total += 1
    return {"total": total, "items": items}


@router.get("/{scope}/module/{module}/download")
def download_module(scope: str, module: str, request: Request):
    settings = get_settings(request)
    filename = MODULE_FILES.get(module.upper())
    if not filename:
        return PlainTextResponse("Unknown module", status_code=400)
    path = settings.OUTPUTS_DIR / scope / filename
    if not path.exists():
        return PlainTextResponse("Not found", status_code=404)

    def iterfile():
        with path.open("rb") as f:
            while chunk := f.read(1024 * 1024):
                yield chunk

    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(iterfile(), media_type="text/plain", headers=headers)


@router.get("/{scope}/module/{module}", response_class=HTMLResponse)
def module_page(
    scope: str,
    module: str,
    # filters (string supaya '' tidak bikin 422)
    q: str | None = None,
    host: str | None = None,
    param: str | None = None,
    http_class: str | None = None,
    codes: str | None = None,
    ctype: str | None = None,
    min_size: str | None = None,
    max_size: str | None = None,
    # paging preferred by _pager.html
    page: int | None = None,
    page_size: int | None = None,
    # legacy (still supported)
    offset: int = 0,
    limit: int = Query(100, le=1000),
    request: Request = None,
    scheme: str | None = None,
):
    templates = get_templates(request)

    # ---- normalize paging ----
    if page_size is not None:
        try:
            limit = max(1, min(1000, int(page_size)))
        except Exception:
            limit = 100
    if page is not None:
        try:
            page = max(1, int(page))
        except Exception:
            page = 1
        offset = (page - 1) * limit
    else:
        page = (offset // limit) + 1 if limit else 1

    # ---- fetch data + ENRICH & FILTER LANJUTAN ----
    settings = get_settings(request)
    filename = MODULE_FILES.get(module.upper())
    path = settings.OUTPUTS_DIR / scope / (filename or "")

    # index enrich
    probe_idx = _load_probe_index(scope, settings.OUTPUTS_DIR)
    # sanity log (opsional)
    # print(f"[enrich] scope={scope} idx_size={len(probe_idx)}", flush=True)

    # parse filter lanjutan
    codes_set = _parse_codes(codes)
    ctype_q = (ctype or "").lower().strip()
    try:
        min_b = int(min_size) if (min_size and str(min_size).strip() != "") else None
    except:
        min_b = None
    try:
        max_b = int(max_size) if (max_size and str(max_size).strip() != "") else None
    except:
        max_b = None

    total, rows = 0, []
    if path.exists():
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                url = line.strip()
                if not url:
                    continue

                # basic filters
                if q and q not in url:
                    continue
                if host and host not in url:
                    continue
                if param and (f"{param}=" not in url):
                    continue

                # enrich lookup (pakai helper robust)
                enr = _lookup_enrich(probe_idx, url)
                code = enr.get("code")
                ctype_val = (enr.get("ctype") or "").lower()
                size_val = enr.get("size")

                # advanced filters
                if codes_set and (code not in codes_set):
                    continue
                if not _match_http_class(code if isinstance(code, int) else None, http_class):
                    continue
                if ctype_q and (ctype_q not in ctype_val):
                    continue
                if min_b is not None and not (isinstance(size_val, (int, float)) and size_val >= min_b):
                    continue
                if max_b is not None and not (isinstance(size_val, (int, float)) and size_val <= max_b):
                    continue
                if scheme and scheme not in ("", "(any)", "any"):
                    if scheme == "http" and not url.startswith("http://"):
                        continue
                    if scheme == "https" and not url.startswith("https://"):
                        continue
                # paginate
                if total >= offset and len(rows) < limit:
                    rows.append({
                        "url": url,
                        "status": enr.get("status") or "-",
                        "code": code if code is not None else "-",
                        "size": _humansize(size_val) if size_val is not None else "-",
                        "title": enr.get("title") or "-",
                        "last_probe": enr.get("ts") or "-",
                        "param_hit": None,
                        "has_query": "?" in url,
                        "scheme": scheme or "",
                    })
                total += 1
    else:
        total, rows = 0, []

    # ---- compute pages window ----
    pages = max((total + limit - 1) // limit, 1)
    window = 7
    start = max(page - 3, 1)
    end = min(start + window - 1, pages)
    start = max(min(start, end - window + 1), 1)
    page_numbers = list(range(start, end + 1))

    # ---- build QS helpers preserving ALL current filters ----
    qs_for_page, qs_prev, qs_next, apply_qs, reset_qs = _build_qs_preserve(
        request, pages=pages, limit=limit, page=page
    )
    print(f"[pager] query: page={page} page_size={limit} raw_qs={str(request.query_params)}", flush=True)
    ctx = {
        "request": request,
        "scope": scope,
        "module_name": module.upper(),

        # list/table data
        "rows": rows,
        "total": total,

        # form state (echo back)
        "q": q or "",
        "host": host or "",
        "param": param or "",
        "http_class": http_class or "",
        "codes": codes or "",
        "ctype": ctype or "",
        "min_size": min_size,
        "max_size": max_size,

        # paging state
        "offset": offset,
        "limit": limit,
        "page": page,
        "pages": pages,
        "page_numbers": page_numbers,

        # pager links
        "qs_prev": qs_prev,
        "qs_next": qs_next,
        "qs_for": qs_for_page,

        # toolbar helpers
        "rows_choices": [50, 100, 200, 500],
        "apply_qs": apply_qs,
        "reset_qs": reset_qs,

        # aliases for _pager.html and htmx
        "total_pages": pages,
        "current_page": page,
        "page_size": limit,
        "page_url": f"/targets/{scope}/module/{module}",
        "page_id": "page",

        # download link
        "download_url": f"/targets/{scope}/module/{module}/download",
        
        "scheme": scheme or "",
    }

    return templates.TemplateResponse("module_generic.html", ctx)


@router.get("/{scope}/module/{module}/api/debug-index.json")
def debug_index(scope: str, module: str, request: Request):
    settings = get_settings(request)
    idx = _load_probe_index(scope, settings.OUTPUTS_DIR)
    sample_keys = list(idx.keys())[:5]
    return {
        "scope": scope,
        "index_size": len(idx),
        "sample_keys": sample_keys,
        "ndjson_path": str(settings.OUTPUTS_DIR / scope / "__cache" / "url_probe.ndjson"),
    }

@router.get("/{scope}/sensitive_paths")
def sensitive_paths_alias(scope: str):
    # route lama -> generic
    return RedirectResponse(url=f"/targets/{scope}/module/sensitive_paths")
