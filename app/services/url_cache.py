# app/services/url_cache.py
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse, urlunparse
from typing import Dict, Any, Iterable
import json
import os
import time
import tempfile

CACHE_DIRNAME = "__cache"

# ---------- paths & io ----------

def _cache_dir(outputs_dir: Path | str, scope: str) -> Path:
    return Path(outputs_dir) / scope / CACHE_DIRNAME

def ensure_cache_dirs(outputs_dir: Path | str, scope: str) -> Path:
    cdir = _cache_dir(outputs_dir, scope)
    cdir.mkdir(parents=True, exist_ok=True)
    return cdir

def _load_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        # kalau rusak, jangan bikin crash
        return {}

def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=str(path.parent)) as tf:
        json.dump(data, tf, ensure_ascii=False)
        tmp_name = tf.name
    os.replace(tmp_name, path)

# ---------- canonicalization ----------

def canon_url(url: str) -> str:
    """
    Normalisasi URL agar stabil sebagai key:
    - lowercase scheme & netloc
    - drop fragment
    - jaga path/query apa adanya (tanpa trailing slash rewrite agresif)
    """
    try:
        pu = urlparse(url)
        scheme = (pu.scheme or "").lower()
        netloc = (pu.netloc or "").lower()
        path = pu.path or "/"
        query = pu.query
        return urlunparse((scheme, netloc, path, "", query, ""))  # no params/fragment
    except Exception:
        return url

# ---------- enrich (gabungan semua sumber) ----------

def get_url_enrich_cached(outputs_dir: Path | str, scope: str) -> Dict[str, Dict[str, Any]]:
    """
    Gabungkan semua file __cache/*_enrich.json menjadi satu dict:
      { canonical_url: {alive, code, size, title, last_probe, ...} }
    """
    cdir = _cache_dir(outputs_dir, scope)
    if not cdir.exists():
        return {}
    merged: Dict[str, Dict[str, Any]] = {}
    # baca semua *_enrich.json (subdomains_enrich.json, sensitive_paths_enrich.json, documents_enrich.json, dst)
    for p in sorted(cdir.glob("*_enrich.json")):
        data = _load_json(p)
        if isinstance(data, dict):
            merged.update(data)
    return merged

def save_url_enrich(outputs_dir: Path | str, scope: str, mapping: Dict[str, Dict[str, Any]], filename: str = "urls_enrich.json") -> Path:
    """
    Simpan mapping URL kanonik => probe record dalam satu berkas (default: urls_enrich.json).
    Dipakai kalau kamu mau satu file agregat.
    """
    cdir = ensure_cache_dirs(outputs_dir, scope)
    path = cdir / filename
    _atomic_write_json(path, mapping)
    return path

def save_module_enrich(outputs_dir: Path | str, scope: str, module: str, mapping: Dict[str, Dict[str, Any]]) -> Path:
    """
    Simpan per modul ke __cache/{module}_enrich.json
    """
    cdir = ensure_cache_dirs(outputs_dir, scope)
    path = cdir / f"{module}_enrich.json"
    _atomic_write_json(path, mapping)
    return path

# ---------- ndjson writer ----------

def ndjson_path(outputs_dir: Path | str, scope: str, name: str = "url_probe.ndjson") -> Path:
    return ensure_cache_dirs(outputs_dir, scope) / name

def ndjson_writer(path: Path):
    """
    Context manager sederhana untuk tulis NDJSON append.
    """
    class _W:
        def __init__(self, p: Path):
            self.f = p.open("a", encoding="utf-8")
        def write(self, obj: dict):
            self.f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        def close(self):
            try:
                self.f.close()
            except Exception:
                pass
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            self.close()
    path.parent.mkdir(parents=True, exist_ok=True)
    return _W(path)

# ---------- upsert helper ----------

def upsert_url_probe(store: Dict[str, Dict[str, Any]], url: str, rec: Dict[str, Any]) -> None:
    """
    Update satu URL canonical di mapping agregat.
    """
    key = canon_url(url)
    prev = store.get(key) or {}
    prev.update(rec)
    store[key] = prev

# ---------- utility kecil ----------

def now_ts() -> int:
    return int(time.time())
