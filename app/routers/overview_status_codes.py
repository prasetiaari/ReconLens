# app/routers/overview_status_codes.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.settings import get_settings

router = APIRouter()


# -------- helpers --------
def _klass(code: Optional[int]) -> str:
    if code is None:
        return "other"
    try:
        k = int(code) // 100
    except Exception:
        return "other"
    return f"{k}xx" if k in (2, 3, 4, 5) else "other"


def _extract_code_from_probe(rec: Dict[str, Any]) -> Optional[int]:
    """
    Robust extractor untuk beragam format baris NDJSON:
    - {"code": 200, ...}
    - {"status": 200, ...}
    - {"resp": {"status": 200, ...}, ...}
    - {"response_code": 200, ...}
    """
    cand = None
    if "code" in rec:
        cand = rec.get("code")
    elif "status" in rec:
        cand = rec.get("status")
    elif isinstance(rec.get("resp"), dict) and "status" in rec["resp"]:
        cand = rec["resp"]["status"]
    elif "response_code" in rec:
        cand = rec.get("response_code")

    # normalisasi -> int atau None
    if isinstance(cand, bool):
        return int(cand)  # unrealistic but safe
    if isinstance(cand, (int, float)):
        return int(cand)
    if isinstance(cand, str):
        return int(cand) if cand.isdigit() else None
    return None


def _iter_probe_lines(probe_path: Path) -> Iterable[Dict[str, Any]]:
    with probe_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if isinstance(rec, dict):
                    yield rec
            except Exception:
                continue


def _scan_probe_files(cache_dir: Path) -> Tuple[Dict[str, int], List[str], int]:
    """
    Scan semua *probe.ndjson di __cache, hitung kelas status-code.
    Return: (counts, used_files, total_lines_seen)
    counts: {"2xx": n, "3xx": n, "4xx": n, "5xx": n, "other": n}
    """
    counts = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
    used: List[str] = []
    total = 0

    if not cache_dir.exists():
        return counts, used, total

    # cari semua file *probe.ndjson (url_probe.ndjson, sensitive_paths_probe.ndjson, dst)
    files = sorted(cache_dir.glob("*probe.ndjson"))
    for p in files:
        used.append(p.name)
        for rec in _iter_probe_lines(p):
            total += 1
            code = _extract_code_from_probe(rec)
            counts[_klass(code)] += 1

    return counts, used, total


def _scan_url_enrich(enrich_path: Path) -> Tuple[Dict[str, int], int]:
    """
    Fallback kalau tidak ada *probe.ndjson.
    Baca __cache/url_enrich.json -> {url: {code/response_code: ...}}
    """
    counts = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
    seen = 0
    if not enrich_path.exists():
        return counts, seen

    try:
        data: Dict[str, Dict[str, Any]] = json.loads(enrich_path.read_text(encoding="utf-8"))
    except Exception:
        return counts, seen

    for _url, rec in data.items():
        seen += 1
        raw = None
        if rec:
            raw = rec.get("code")
            if raw is None:
                raw = rec.get("response_code")
        if isinstance(raw, str):
            raw = int(raw) if raw.isdigit() else None
        elif isinstance(raw, (float, bool)):
            raw = int(raw)
        counts[_klass(raw)] += 1

    return counts, seen


# -------- route --------
@router.get("/targets/{scope}/api/overview/status-codes.json", response_class=JSONResponse)
def overview_status_codes(scope: str, request: Request) -> Any:
    """
    Aggregasi cepat jumlah status-code classes untuk overview dashboard.
    Prioritas sumber:
      1) __cache/*probe.ndjson  (paling akurat & terbaru)
      2) fallback: __cache/url_enrich.json
    """
    settings = get_settings(request)
    base = Path(settings.OUTPUTS_DIR) / scope / "__cache"

    counts, used_files, total_lines = _scan_probe_files(base)

    source = "probe"
    records = total_lines
    if sum(counts.values()) == 0:
        # fallback ke url_enrich.json
        enrich_file = base / "url_enrich.json"
        counts, seen = _scan_url_enrich(enrich_file)
        source = "url_enrich"
        records = seen
        used_files = [enrich_file.name] if enrich_file.exists() else []

    out = {
        "meta": {
            "scope": scope,
            "records": records,
        },
        "items": [
            {"klass": "2xx", "count": counts["2xx"]},
            {"klass": "3xx", "count": counts["3xx"]},
            {"klass": "4xx", "count": counts["4xx"]},
            {"klass": "5xx", "count": counts["5xx"]},
            {"klass": "other", "count": counts["other"]},
        ],
    }

    # ?debug=1 untuk lihat dari mana data diambil
    dbg = request.query_params.get("debug")
    if dbg is not None and dbg != "" and dbg != "0" and dbg.lower() != "false":
        out["meta"]["source"] = source
        out["meta"]["used_files"] = used_files
        out["meta"]["outputs_dir"] = str(Path(settings.OUTPUTS_DIR))
        out["meta"]["cache_dir"] = str(base)

    return out
