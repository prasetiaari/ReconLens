# app/routers/graphs/api_status_codes.py
from __future__ import annotations

import json
from collections import defaultdict
from glob import glob
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Set, Tuple
from urllib.parse import urlsplit

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from app.core.settings import get_settings

router = APIRouter()


# ---------------- helpers ----------------
def _split_csv(s: str | None) -> List[str]:
    if not s:
        return []
    return [p.strip() for p in s.split(",") if p.strip()]


def _klass(code: int | None) -> str:
    if code is None:
        return "other"
    k = int(code) // 100
    return f"{k}xx" if k in (2, 3, 4, 5) else "other"


def _host_of_url(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def _coerce_code(rec: Dict[str, Any] | None) -> int | None:
    if not rec:
        return None
    raw = rec.get("code")
    if raw is None:
        raw = rec.get("response_code")  # fallback data lama
    if raw in (None, "", "None"):
        return None
    try:
        if isinstance(raw, str):
            return int(raw) if raw.isdigit() else None
        if isinstance(raw, (int, float, bool)):
            return int(raw)
    except Exception:
        return None
    return None


def _load_enrich_dicts(outputs_dir: Path, scope: str, wanted_modules: Set[str]) -> List[Tuple[str, Dict[str, Any]]]:
    cache_dir = outputs_dir / scope / "__cache"
    out: List[Tuple[str, Dict[str, Any]]] = []

    candidates: List[Tuple[str, Path]] = []
    if wanted_modules:
        for m in wanted_modules:
            p = cache_dir / f"{m}_enrich.json"
            if p.exists():
                candidates.append((m, p))
    else:
        for fp in glob(str(cache_dir / "*_enrich.json")):
            p = Path(fp)
            m = p.name.removesuffix("_enrich.json")
            candidates.append((m, p))

    if not candidates:
        p = cache_dir / "url_enrich.json"
        if p.exists():
            candidates.append(("__url_enrich__", p))

    for src, path in candidates:
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(d, dict) and d:
                out.append((src, d))
        except Exception:
            pass

    return out


# -------------- API: rollup status-codes --------------
@router.get("/targets/{scope}/api/graphs/status-codes.json", response_class=JSONResponse)
def status_codes_json(scope: str, request: Request) -> Any:
    """
    Ringkas status-code classes per module dari file enrich.
    Query:
      - modules: CSV (kosong = semua)
      - host_contains: substring pada host
      - host_exact:    host eksak
    """
    settings = get_settings(request)
    outputs_dir = Path(settings.OUTPUTS_DIR)

    qp = request.query_params
    wanted_modules: Set[str] = set(_split_csv(qp.get("modules")))
    host_contains = (qp.get("host_contains") or "").strip().lower()
    host_exact = (qp.get("host_exact") or "").strip().lower()

    src_dicts = _load_enrich_dicts(outputs_dir, scope, wanted_modules)
    if not src_dicts:
        return {
            "modules": {},
            "total": {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0},
            "meta": {
                "scope": scope,
                "records": 0,
                "filtered_modules": sorted(list(wanted_modules)) if wanted_modules else [],
                "host_exact": host_exact or None,
                "host_contains": host_contains or None,
                "modules_available": [],
                "sources": [],
                "note": "no enrich files found",
            },
        }

    classes = ("2xx", "3xx", "4xx", "5xx", "other")
    modules: DefaultDict[str, DefaultDict[str, int]] = defaultdict(lambda: defaultdict(int))
    total = {c: 0 for c in classes}
    seen_urls: Set[str] = set()
    modules_available: Set[str] = set()
    records_count = 0

    for src_name, enrich in src_dicts:
        records_count += len(enrich)
        for url, rec in enrich.items():
            if not isinstance(rec, dict):
                continue

            sources = rec.get("sources") or []
            if not isinstance(sources, list):
                sources = [sources] if sources else []
            for s in sources:
                if isinstance(s, str) and s:
                    modules_available.add(s)

            if wanted_modules and not (set(sources) & wanted_modules):
                continue

            host = _host_of_url(url)
            if host_exact and host != host_exact:
                continue
            if host_contains and host_contains not in host:
                continue

            code = _coerce_code(rec)
            klass = _klass(code)

            if sources:
                for m in sources:
                    modules[m][klass] += 1
            else:
                modules["(unknown)"][klass] += 1

            if url not in seen_urls:
                seen_urls.add(url)
                total[klass] += 1

    modules_out = {m: {c: int(cnts.get(c, 0)) for c in classes} for m, cnts in modules.items()}

    return {
        "modules": modules_out,
        "total": {c: int(total.get(c, 0)) for c in classes},
        "meta": {
            "scope": scope,
            "records": records_count,
            "filtered_modules": sorted(list(wanted_modules)) if wanted_modules else [],
            "host_exact": host_exact or None,
            "host_contains": host_contains or None,
            "modules_available": sorted(list(modules_available)) or list(modules_out.keys()),
            "sources": [name for name, _ in src_dicts],
        },
    }


# -------------- API: drilldown list (bar/pie click) --------------
@router.get("/targets/{scope}/api/graphs/status-codes/list.json", response_class=JSONResponse)
def status_codes_list(
    scope: str,
    request: Request,
    module: str = Query(..., description="nama module, mis. sensitive_paths"),
    klass: str = Query(..., description="2xx|3xx|4xx|5xx|other"),
    host_q: str | None = Query(None, description="substring di host (opsional)"),
    q: str | None = Query(None, description="substring di URL penuh (opsional)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
) -> Any:
    """
    Kembalikan daftar URL untuk module + kelas status tertentu, dengan paging.
    Dipakai saat user klik bar/pie.
    """
    settings = get_settings(request)
    outputs_dir = Path(settings.OUTPUTS_DIR)

    wanted_modules: Set[str] = {module} if module else set()
    src_dicts = _load_enrich_dicts(outputs_dir, scope, wanted_modules)

    rows: List[Dict[str, Any]] = []
    total = 0

    for _src_name, enrich in src_dicts:
        for url, rec in enrich.items():
            if not isinstance(rec, dict):
                continue

            sources = rec.get("sources") or []
            if not isinstance(sources, list):
                sources = [sources] if sources else []
            if module and (module not in sources):
                continue

            # filter host/url substring (opsional)
            host = _host_of_url(url)
            if host_q and host_q.lower() not in host:
                continue
            if q and q.lower() not in url.lower():
                continue

            code = _coerce_code(rec)
            if _klass(code) != klass:
                continue

            total += 1
            rows.append({
                "url": rec.get("final_url") or url,
                "host": host or None,
                "code": code,
                "size": rec.get("size"),
                "title": rec.get("title"),
                "content_type": rec.get("content_type"),
                "last_probe": rec.get("last_probe"),
            })

    # paging
    rows.sort(key=lambda r: (r["host"] or "", r["url"]))
    start = (page - 1) * page_size
    end = start + page_size
    page_rows = rows[start:end]
    pages = max(1, (total + page_size - 1) // page_size)

    return {
        "rows": page_rows,
        "meta": {
            "scope": scope,
            "module": module,
            "klass": klass,
            "total": total,
            "page": page,
            "pages": pages,
            "page_size": page_size,
        },
    }
