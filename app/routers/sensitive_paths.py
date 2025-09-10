# app/routers/sensitive_paths.py
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Tuple, List, Optional, Set
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.core.settings import get_settings
from app.core.templates import get_templates
from app.core.fs import iter_lines
from app.services.enrich_urls import (
    get_url_enrich_cached,
    canon_url,
)

router = APIRouter()


# ----------------- helpers -----------------
def _first_param(request: Request, *names: str) -> Optional[str]:
    qp = request.query_params
    for n in names:
        v = qp.get(n)
        if v is not None and v != "":
            return v
    return None


def _alive_flag(request: Request) -> bool:
    q = request.query_params
    v = q.get("alive") or q.get("live") or q.get("only_live")
    return (v is not None) and (v not in ("0", "false", "False", "off", ""))


def _parse_codes(s: Optional[str]) -> Set[int]:
    if not s:
        return set()
    out: Set[int] = set()
    for p in s.split(","):
        p = p.strip()
        if not p:
            continue
        if p.isdigit():
            out.add(int(p))
    return out


def _parse_classes(s: Optional[str]) -> Set[str]:
    # "(any)" | "2xx,3xx,401,403" -> {"2xx","3xx","401","403"}
    if not s:
        return set()
    v = s.strip().lower()
    if v in {"(any)", "any"}:
        return set()
    return {p.strip().lower() for p in v.split(",") if p.strip()}


def _parse_ctype(s: Optional[str]) -> Set[str]:
    if not s:
        return set()
    return {p.strip().lower() for p in s.split(",") if p.strip()}


def _parse_int(s: Optional[str]) -> Optional[int]:
    try:
        return int(s) if s is not None and s != "" else None
    except Exception:
        return None


def _status_class_match(code: Optional[int], klasses: Set[str], codes: Set[int]) -> bool:
    # 1) exact codes (override)
    # 2) class/ exact in klasses
    if not klasses and not codes:
        return True
    if code is None:
        return False
    if codes:
        return code in codes
    if str(code) in klasses:
        return True
    c = code // 100
    return f"{c}xx" in klasses


def _ctype_match(ct: Optional[str], wanted: Set[str]) -> bool:
    if not wanted:
        return True
    if not ct:
        return False
    lo = ct.lower()
    return any(w in lo for w in wanted)


def _size_match(sz: Optional[int], min_sz: Optional[int], max_sz: Optional[int]) -> bool:
    if sz is None:
        return False if (min_sz is not None or max_sz is not None) else True
    if min_sz is not None and sz < min_sz:
        return False
    if max_sz is not None and sz > max_sz:
        return False
    return True


# ----------------- iterator + paging -----------------
def _iter_urls_filtered(
    path: Path,
    q: str,
    enrich: dict,
    alive_only: bool,
    codes: Set[int],
    klasses: Set[str],
    ctypes: Set[str],
    min_size: Optional[int],
    max_size: Optional[int],
) -> Iterable[str]:
    q_lower = q.lower() if q else ""
    for line in iter_lines(path):
        url = line.strip()
        if not url:
            continue
        if q_lower and q_lower not in url.lower():
            continue

        rec = enrich.get(canon_url(url))

        if alive_only:
            if not rec or not bool(rec.get("alive")):
                continue

        code = rec.get("code") if rec else None
        if not _status_class_match(code, klasses, codes):
            continue

        ct = rec.get("content_type") if rec else None
        if not _ctype_match(ct, ctypes):
            continue

        size = rec.get("size") if rec else None
        if not _size_match(size, min_size, max_size):
            continue

        yield url


def _paginate_iter(it: Iterable[str], page: int, page_size: int) -> Tuple[List[str], int, int, bool, bool]:
    start = max(0, (page - 1) * page_size)
    end = start + page_size

    rows: List[str] = []
    total = 0
    for total, url in enumerate(it, start=1):
        if start < total <= end:
            rows.append(url)

    total_pages = max(1, (total + page_size - 1) // page_size)
    has_prev = page > 1
    has_next = page < total_pages
    return rows, total, total_pages, has_prev, has_next


# ----------------- routes -----------------
@router.get("/targets/{scope}/sensitive_paths", response_class=HTMLResponse)
async def sensitive_paths_page(scope: str, request: Request):
    settings = get_settings(request)
    templates = get_templates(request)

    # basic
    q = request.query_params.get("q") or ""
    page = int(_first_param(request, "page") or 1)
    page_size = int(_first_param(request, "page_size", "per_page", "rows", "rows_per_page") or 100)
    alive = _alive_flag(request)

    # filters
    codes = _parse_codes(_first_param(request, "codes", "code"))
    http_class_raw = (_first_param(request, "http_class", "class") or "(any)").strip()
    klasses = _parse_classes(http_class_raw)
    ctypes = _parse_ctype(_first_param(request, "ct", "ctype"))
    min_size = _parse_int(_first_param(request, "min_size", "min"))
    max_size = _parse_int(_first_param(request, "max_size", "max"))

    outputs_dir = Path(settings.OUTPUTS_DIR)
    page_url = f"/targets/{scope}/sensitive_paths"

    txt_file = outputs_dir / scope / "sensitive_paths.txt"
    enrich = get_url_enrich_cached(outputs_dir, scope, "sensitive_paths") or {}

    it = _iter_urls_filtered(
        txt_file, q, enrich, alive_only=alive,
        codes=codes, klasses=klasses, ctypes=ctypes,
        min_size=min_size, max_size=max_size,
    )
    rows, total, total_pages, has_prev, has_next = _paginate_iter(it, page, page_size)

    # -------- persist filters across page navigation --------
    persist_qs_params = {}
    if q:
        persist_qs_params["q"] = q
    if codes:
        persist_qs_params["codes"] = ",".join(map(str, sorted(codes)))
    if klasses:
        # simpan raw agar dropdown bisa tetap menunjuk "(any)" / "2xx" / dll persis input
        persist_qs_params["http_class"] = http_class_raw
    if ctypes:
        persist_qs_params["ctype"] = ",".join(sorted(ctypes))
    if min_size is not None:
        persist_qs_params["min_size"] = str(min_size)
    if max_size is not None:
        persist_qs_params["max_size"] = str(max_size)
    persist_qs = urlencode(persist_qs_params)

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
        "total_pages": total_pages,
        "has_prev": has_prev,
        "has_next": has_next,

        "enrich": enrich,
        "canon": canon_url,

        # echoes for form
        "codes": ",".join(map(str, sorted(codes))) if codes else "",
        "klasses": ",".join(sorted(klasses)) if klasses else "",
        "ctypes": ",".join(sorted(ctypes)) if ctypes else "",
        "min_size": min_size,
        "max_size": max_size,
        "http_class": http_class_raw,

        # NEW: dipakai script di template agar pager link bawa filter
        "persist_qs": persist_qs,
    }
    return templates.TemplateResponse("sensitive_paths.html", ctx)


@router.get("/targets/{scope}/sensitive_paths/rows", response_class=HTMLResponse)
async def sensitive_paths_rows(scope: str, request: Request):
    # render halaman penuh (hx-select="#page" tetap kompatibel)
    return await sensitive_paths_page(scope, request)
