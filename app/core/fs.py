from __future__ import annotations
from pathlib import Path
from typing import Iterable, Iterator
import math, re
_LINECOUNT_CACHE = {}

DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)

def list_subdirs(p: Path) -> list[str]:
    if not p.exists():
        return []
    return sorted([
        x.name
        for x in p.iterdir()
        if x.is_dir() and DOMAIN_RE.match(x.name)
    ])

def safe_join(root: Path, *parts: str) -> Path:
    p = (root.joinpath(*parts)).resolve()
    if root.resolve() not in p.parents and p != root.resolve():
        raise ValueError("Path traversal detected")
    return p

def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    # fast-ish line count
    total = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            total += chunk.count(b"\n")
    return total

def iter_lines(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            yield line.rstrip("\r\n")

def page_lines(path: Path, page: int, page_size: int, q: str | None = None) -> tuple[list[str], int]:
    """
    Stream page tanpa load seluruh file. Filter substring jika q ada.
    Return (items, total_filtered).
    """
    if not path.exists():
        return [], 0

    # naive filter pass: scan dan collect window untuk paging
    items: list[str] = []
    total = 0
    start = (page - 1) * page_size
    end = start + page_size

    for line in iter_lines(path):
        if q and q not in line:
            continue
        if total >= start and total < end:
            items.append(line)
        total += 1
        if total >= end and (not q):
            break
    return items, total

_LINECOUNT_CACHE = {}  # (str(path), mtime) -> total lines

def get_line_count_cached(path: Path) -> int:
    try:
        st = path.stat()
    except FileNotFoundError:
        return 0
    key = (str(path), st.st_mtime)
    if key in _LINECOUNT_CACHE:
        return _LINECOUNT_CACHE[key]
    # invalidate entry lama utk file ini
    for k in [k for k in _LINECOUNT_CACHE if k[0] == str(path)]:
        _LINECOUNT_CACHE.pop(k, None)
    total = 0
    with path.open("rb", buffering=0) as f:
        while True:
            chunk = f.read(1 << 20)  # 1 MB
            if not chunk:
                break
            total += chunk.count(b"\n")
    _LINECOUNT_CACHE[key] = total
    return total

def count_lines_filtered(path: Path, needle: str) -> int:
    if not path.exists():
        return 0
    q = needle.lower()
    n = 0
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if q in line.lower():
                n += 1
    return n

def paginate_file(path: Path, page: int, page_size: int, q: str):
    """Return (rows, total, total_pages) — total dihitung terpisah dari page_lines."""
    from app.core.fs import page_lines  # pakai yang sudah early-break
    rows, _ = page_lines(path, page=page, page_size=page_size, q=q)
    total = count_lines_filtered(path, q) if q else get_line_count_cached(path)
    total_pages = max(1, math.ceil(total / max(1, page_size)))
    return rows, total, total_pages
