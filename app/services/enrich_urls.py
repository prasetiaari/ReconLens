# urls_parser/app/services/enrich_urls.py
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, Any, Tuple
from urllib.parse import urlsplit, urlunsplit

CACHE_DIRNAME = "__cache"
URL_ENRICH_NAME = "url_enrich.json"

# in-memory cache (per file path)
_ENRICH_CACHE: Dict[Path, Dict[str, Any]] = {}
_ENRICH_MTIME: Dict[Path, float] = {}


# ---------- Canonicalization -------------------------------------------------
def canon_url(u: str) -> str:
    """
    Normalisasi URL agar key cocok antara CLI & UI:
    - scheme lower, host lower
    - hilangkan fragment
    - path default "/" untuk kosong
    - buang port default 80/443
    - JANGAN buang query (penting untuk beberapa path)
    - hapus trailing slash kecuali "/"
    """
    try:
        s = urlsplit(u.strip())
        scheme = (s.scheme or "http").lower()
        host = (s.hostname or "").lower()
        port = s.port
        netloc = host
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            netloc = f"{host}:{port}"
        path = s.path or "/"
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        # keep query, drop fragment
        return urlunsplit((scheme, netloc, path, s.query, ""))
    except Exception:
        return u


# ---------- Paths ------------------------------------------------------------
def _cache_dir(outputs_dir: Path | str, scope: str) -> Path:
    return Path(outputs_dir) / scope / CACHE_DIRNAME

def url_enrich_path(outputs_dir: Path | str, scope: str) -> Path:
    return _cache_dir(outputs_dir, scope) / URL_ENRICH_NAME

def module_enrich_path(outputs_dir: Path | str, scope: str, module: str) -> Path:
    return _cache_dir(outputs_dir, scope) / f"{module}_enrich.json"


# ---------- IO helpers -------------------------------------------------------
def _read_json_memo(p: Path) -> Dict[str, Any]:
    mt = p.stat().st_mtime if p.exists() else 0.0
    if p not in _ENRICH_CACHE or _ENRICH_MTIME.get(p) != mt:
        data: Dict[str, Any] = {}
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                data = {}
        _ENRICH_CACHE[p] = data
        _ENRICH_MTIME[p] = mt
    return _ENRICH_CACHE[p]

def save_enrich_map_atomic(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)
    # refresh memo
    _ENRICH_CACHE[path] = data
    _ENRICH_MTIME[path] = path.stat().st_mtime


# ---------- Public API -------------------------------------------------------
def get_url_enrich_cached(outputs_dir: Path | str, scope: str, module: str) -> Dict[str, Any]:
    """
    Baca peta enrich untuk modul tertentu. Urutan:
      1) <scope>/__cache/<module>_enrich.json
      2) <scope>/__cache/url_enrich.json (fallback)
    """
    p1 = module_enrich_path(outputs_dir, scope, module)
    if p1.exists():
        return _read_json_memo(p1)
    p2 = url_enrich_path(outputs_dir, scope)
    if p2.exists():
        return _read_json_memo(p2)
    return {}


def merge_into_url_enrich(outputs_dir: Path | str, scope: str, module_map: Dict[str, Any]) -> None:
    """
    Merge module_map (hasil probe modul tertentu) ke url_enrich.json
    """
    p = url_enrich_path(outputs_dir, scope)
    base = _read_json_memo(p) if p.exists() else {}
    base.update(module_map)
    save_enrich_map_atomic(p, base)


# ---------- small utils (opsional dipakai di tempat lain) -------------------
def now_ts() -> int:
    return int(time.time())
