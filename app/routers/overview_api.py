
# app/routers/overview_api.py
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from app.core.settings import get_settings

router = APIRouter()

PROBE_FILENAMES = [
    "subdomains_probe.ndjson",
    "sensitive_paths_probe.ndjson",
    "url_probe.ndjson",
]

@dataclass
class ProbeRow:
    url: str
    host: Optional[str]
    content_type: Optional[str]
    module: Optional[str]

def _iter_probe_rows(cache_dir: Path) -> Iterable[ProbeRow]:
    for name in PROBE_FILENAMES:
        f = cache_dir / name
        if not f.exists():
            continue
        with f.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                url = obj.get("url") or obj.get("final_url") or ""
                host = obj.get("host")
                ct = obj.get("content_type")
                module = obj.get("module") or obj.get("source")  # toleransi schema lama
                yield ProbeRow(url=url, host=host, content_type=ct, module=module)

def _newer_than(target: Path, sources: List[Path]) -> bool:
    """Return True bila `target` lebih baru dari semua `sources` (aman dipakai)."""
    if not target.exists():
        return False
    t_mtime = target.stat().st_mtime
    for s in sources:
        if s.exists() and s.stat().st_mtime > t_mtime:
            return False
    return True

@router.get("/targets/{scope}/api/overview/content-types.json", response_class=JSONResponse)
def content_types_overview(
    scope: str,
    request: Request,
    module: Optional[str] = Query(default=None, description="Filter 1 modul"),
    host_contains: Optional[str] = Query(default=None),
    host_exact: Optional[str] = Query(default=None),
    limit: int = Query(default=5, ge=1, le=50),
) -> Any:
    """
    Top content-types (gabungan file *_probe.ndjson).
    Filter: module, host_contains, host_exact.
    Cache file: __cache/overview_ctypes.json
    """
    settings = get_settings(request)
    cache_dir = Path(settings.OUTPUTS_DIR) / scope / "__cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    cache_file = cache_dir / "overview_ctypes.json"
    sources = [cache_dir / n for n in PROBE_FILENAMES]

    # pakai cache kalau masih valid (dan tidak ada filter tambahan selain limit)
    use_cache = (module is None and not host_contains and not host_exact)
    if use_cache and _newer_than(cache_file, sources):
        try:
            payload = json.loads(cache_file.read_text(encoding="utf-8"))
            # batasi limit jika diminta lebih kecil dari yang tersimpan
            if "items" in payload and isinstance(payload["items"], list) and len(payload["items"]) > limit:
                payload["items"] = payload["items"][:limit]
            return payload
        except Exception:
            pass  # jika cache korup, regenerasi

    # hitung ulang
    counter: Counter[str] = Counter()
    total = 0
    mod_norm = (module or "").strip().lower()

    for row in _iter_probe_rows(cache_dir):
        if mod_norm and (row.module or "").lower() != mod_norm:
            continue
        if host_exact and (row.host or "") != host_exact:
            continue
        if host_contains and (host_contains not in (row.host or "")):
            continue

        ct = (row.content_type or "").strip().lower()
        if not ct:
            ct = "(unknown)"
        counter[ct] += 1
        total += 1

    items = [{"ctype": k, "count": v} for k, v in counter.most_common(limit)]
    payload = {
        "meta": {
            "scope": scope,
            "records": total,
            "module": module,
            "limit": limit,
            "source": "probe",
        },
        "items": items,
    }

    # simpan cache bila tanpa filter (biar cepat dipakai Overview)
    if use_cache:
        try:
            cache_file.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    return payload
