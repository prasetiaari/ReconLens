from __future__ import annotations
from pathlib import Path
from fastapi import HTTPException
from app.core.fs import safe_join, count_lines, page_lines
from typing import Dict, List, Tuple, Optional
import io
import os
# ==== CACHE GLOBAL BERDASARKAN PATH + MTIME ====
# key: (str(path), mtime_float) -> {"lines": int}
_LINECOUNT_CACHE: Dict[Tuple[str, float], Dict[str, int]] = {}


def module_file(outputs_dir: Path, scope: str, modules_map: dict, module: str) -> Path:
    fname = modules_map.get(module)
    if not fname:
        raise HTTPException(status_code=404, detail=f"Unknown module: {module}")
    fp = safe_join(outputs_dir, scope, fname)
    if not fp.exists():
        raise HTTPException(status_code=404, detail=f"File not found for module {module}")
    return fp

def module_count(outputs_dir: Path, scope: str, modules_map: dict, module: str) -> int:
    return count_lines(module_file(outputs_dir, scope, modules_map, module))

def module_page(outputs_dir: Path, scope: str, modules_map: dict, module: str, page: int, page_size: int, q: str | None):
    fp = module_file(outputs_dir, scope, modules_map, module)
    return page_lines(fp, page=page, page_size=page_size, q=q)
def _fast_count_lines(path: Path, chunk_size: int = 1 << 20) -> int:
    """Hitung jumlah baris cepat tanpa memuat seluruh file ke memori."""
    # pakai buffered read, portable (tanpa 'wc -l')
    total = 0
    with path.open("rb", buffering=0) as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            total += b.count(b"\n")
    return total

def get_line_count_cached(path: Path) -> int:
    """Ambil jumlah baris dari cache jika mtime sama; kalau beda, hitung ulang & simpan."""
    try:
        st = path.stat()
    except FileNotFoundError:
        return 0
    key = (str(path), st.st_mtime)
    cached = _LINECOUNT_CACHE.get(key)
    if cached:
        return cached["lines"]
    # invalidasi entry lama untuk path yang sama (hemat memori)
    # (opsional) hapus semua key lama untuk path ini
    to_del = [k for k in _LINECOUNT_CACHE if k[0] == str(path)]
    for k in to_del:
        _LINECOUNT_CACHE.pop(k, None)
    # hitung baru
    lines = _fast_count_lines(path)
    _LINECOUNT_CACHE[key] = {"lines": lines}
    return lines

def get_file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0

# ==== GANTI build_module_stats supaya pakai cache ====
def build_module_stats(outputs_dir: Path, scope: str, modules: Dict[str, Dict]) -> List[Dict]:
    """
    Return list of dicts: [{"module": "...", "file": "subdomains.txt", "size_bytes": 123, "lines": 456}, ...]
    Tanpa membaca seluruh file setiap request (pakai cache mtime).
    """
    out_dir = outputs_dir / scope
    results: List[Dict] = []
    filemap = {m["name"]: m.get("file", f"{m['name']}.txt") for m in modules.values()} if isinstance(modules, dict) else {}

    # fallback kalau modules berupa list/tuple
    if not filemap:
        # ekspektasi ada struktur serupa di settings.MODULES
        pass

    for module_name, filename in filemap.items():
        p = out_dir / filename
        size = get_file_size(p)
        lines = get_line_count_cached(p) if size > 0 else 0
        results.append({
            "module": module_name,
            "file": filename,
            "size_bytes": size,
            "lines": lines,
        })
    # bisa di-sort jika mau
    # results.sort(key=lambda x: x["module"])
    return results
