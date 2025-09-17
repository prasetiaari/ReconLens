# app/services/wordlists.py
from __future__ import annotations
import os
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

# --- config ---
# Bisa dioverride via ENV WORDLISTS_DIR, atau set default ke data/wordlists (relatif project root)
DEFAULT_DIR = "data/wordlists"
MAX_PREVIEW_BYTES = 64 * 1024  # 64 KB
ALLOWED_EXTS = {".txt", ".lst", ".wordlist", ".wl"}  # boleh tambah sesuai kebutuhan

def _human_size(n: int) -> str:
    if n is None:
        return "-"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    return f"{f:.1f} {units[i]}"

def get_wordlists_dir() -> Path:
    """Ambil folder wordlists (ENV > default), pastikan absolute Path."""
    base = os.environ.get("WORDLISTS_DIR", DEFAULT_DIR)
    p = Path(base).expanduser().resolve()
    return p

def list_wordlists() -> List[Dict]:
    """
    Scan folder wordlists & kembalikan daftar file.
    Tiap item: {name, path, size_bytes, size_human, mtime_iso}
    """
    root = get_wordlists_dir()
    out: List[Dict] = []
    if not root.exists():
        return out
    for p in sorted(root.iterdir()):
        if not p.is_file():
            continue
        if ALLOWED_EXTS and p.suffix.lower() not in ALLOWED_EXTS:
            continue
        try:
            st = p.stat()
        except Exception:
            continue
        out.append({
            "name": p.name,
            "path": str(p.resolve()),
            "size_bytes": st.st_size,
            "size_human": _human_size(st.st_size),
            "mtime_iso": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
        })
    return out

def resolve_wordlist(name_or_path: str) -> Optional[Path]:
    """
    Terima input dari UI (biasanya filename dari dropdown).
    - Jika absolute path: dipakai hanya jika berada DI DALAM root wordlists.
    - Jika filename: resolve ke root/filename (kalau ada).
    Return Path absolut atau None jika tidak valid.
    """
    if not name_or_path:
        return None
    root = get_wordlists_dir()
    cand = Path(name_or_path).expanduser()
    if cand.is_absolute():
        try:
            real = cand.resolve()
        except Exception:
            return None
        # keamanan: harus berada di bawah root
        if str(real).startswith(str(root.resolve())) and real.exists() and real.is_file():
            return real
        return None
    # filename relatif (umumnya dari dropdown)
    real = (root / name_or_path).resolve()
    try:
        if str(real).startswith(str(root.resolve())) and real.exists() and real.is_file():
            return real
    except Exception:
        pass
    return None

def preview_wordlist(name_or_path: str, max_bytes: int = MAX_PREVIEW_BYTES) -> List[str]:
    """
    Baca sebagian isi wordlist (untuk preview UI jika nanti dibutuhkan).
    """
    path = resolve_wordlist(name_or_path)
    if not path:
        return []
    try:
        data = path.read_bytes()[:max_bytes]
        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        return lines[:50]  # batasi jumlah baris
    except Exception:
        return []
