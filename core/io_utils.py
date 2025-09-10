# urls_parser/core/io_utils.py
from __future__ import annotations

import gzip
import io
import os
import tempfile
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple
import heapq

# ---------------------------
# Path & basic filesystem
# ---------------------------

def ensure_dir(path: os.PathLike | str) -> Path:
    """
    Pastikan direktori 'path' ada. 
    Boleh berupa folder ataupun path file (akan dibuat parent-nya).
    """
    p = Path(path)
    target = p if p.suffix == "" else p.parent
    target.mkdir(parents=True, exist_ok=True)
    return p


def is_gzip_path(path: os.PathLike | str) -> bool:
    return str(path).lower().endswith(".gz")


# ---------------------------
# Readers
# ---------------------------

def read_lines(path: os.PathLike | str, strip: bool = True) -> Iterator[str]:
    """
    Generator baris dari file teks. Support .gz
    - strip=True: trim newline & spasi kanan-kiri.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Input not found: {p}")

    if is_gzip_path(p):
        with gzip.open(p, mode="rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                yield line.strip() if strip else line
    else:
        with open(p, mode="rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                yield line.strip() if strip else line


def read_nonempty_lines(path: os.PathLike | str) -> Iterator[str]:
    """Seperti read_lines, tapi skip baris kosong setelah strip()."""
    for line in read_lines(path, strip=True):
        if line:
            yield line


# ---------------------------
# Writers (atomic)
# ---------------------------

def _atomic_write_bytes(dest_path: Path, data: bytes) -> None:
    """
    Tulis bytes ke file secara atomic:
    - tulis ke temp file di folder yang sama
    - fsync, lalu rename -> menghindari partial write
    """
    ensure_dir(dest_path)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=".tmp_", dir=str(dest_path.parent))
    try:
        with os.fdopen(tmp_fd, "wb") as tmp:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_name, dest_path)  # atomic di dalam filesystem yang sama
    finally:
        try:
            if os.path.exists(tmp_name):
                os.remove(tmp_name)
        except Exception:
            pass


def write_text(path: os.PathLike | str, text: str) -> None:
    """Tulis teks (UTF-8) secara atomic."""
    p = Path(path)
    _atomic_write_bytes(p, text.encode("utf-8"))


def write_lines_simple(
    path: os.PathLike | str,
    lines: Iterable[str],
    dedup: bool = True,
    sort_lines: bool = True,
    trailing_newline: bool = True,
) -> Tuple[int, int]:
    """
    Tulis lines ke TXT (atau .gz) secara atomic.
    - dedup True: hilangkan duplikat (in-memory set)
    - sort_lines True: urutkan alfabet
    Return: (count_input, count_written)
    NOTE: untuk dataset sangat besar, pertimbangkan write_lines_external_sort().
    """
    p = Path(path)
    ensure_dir(p)

    # kumpulkan (in-memory)
    count_in = 0
    if dedup:
        bag = set()
        for ln in lines:
            count_in += 1
            if ln:
                bag.add(ln)
        sorted_lines = sorted(bag) if sort_lines else list(bag)
        payload = "\n".join(sorted_lines)
    else:
        buf: List[str] = []
        for ln in lines:
            count_in += 1
            if ln:
                buf.append(ln)
        if sort_lines:
            buf.sort()
        payload = "\n".join(buf)

    if trailing_newline and payload and not payload.endswith("\n"):
        payload += "\n"

    if is_gzip_path(p):
        data = gzip.compress(payload.encode("utf-8"))
        _atomic_write_bytes(p, data)
    else:
        write_text(p, payload)

    count_out = 0
    if dedup:
        count_out = len(sorted_lines) if sort_lines else (len(bag) if 'bag' in locals() else 0)
    else:
        count_out = len(payload.splitlines()) if payload else 0
    return count_in, count_out


# ---------------------------
# External sort (hemat RAM)
# ---------------------------

def write_lines_external_sort(
    path: os.PathLike | str,
    lines: Iterable[str],
    chunk_size: int = 500_000,
    dedup: bool = True,
    trailing_newline: bool = True,
) -> Tuple[int, int]:
    """
    Menulis lines berukuran sangat besar dengan memory terbatas (chunked external sort):
    1) Pecah menjadi chunk (max chunk_size), dedup per chunk, sort, simpan temp file
    2) K-ways merge semua temp file (heapq.merge), optional dedup global saat merge
    Return: (count_input, count_written)

    Catatan:
    - chunk_size = jumlah baris per potongan (bukan bytes).
    - Lebih lambat dari in-memory, tapi hemat RAM drastis.
    """
    p = Path(path)
    ensure_dir(p)

    temp_files: List[Path] = []
    count_in = 0
    chunk: List[str] = []

    def flush_chunk(ch: List[str]) -> None:
        if not ch:
            return
        if dedup:
            ch = sorted(set(ch))
        else:
            ch.sort()
        # tulis chunk ke temp file (plain text)
        fd, tmp_name = tempfile.mkstemp(prefix=".chunk_", dir=str(p.parent))
        os.close(fd)
        tmp_path = Path(tmp_name)
        with open(tmp_path, "wt", encoding="utf-8", newline="\n") as out:
            out.write("\n".join(ch))
            out.write("\n")
        temp_files.append(tmp_path)
        ch.clear()

    # 1) kumpulkan & flush per chunk
    for ln in lines:
        count_in += 1
        if not ln:
            continue
        chunk.append(ln)
        if len(chunk) >= chunk_size:
            flush_chunk(chunk)
    flush_chunk(chunk)

    # 2) merge semua chunk terurut
    #    - open semua file sebagai iterator
    iters: List[Iterator[str]] = []
    try:
        for f in temp_files:
            fh = open(f, "rt", encoding="utf-8", errors="replace")
            # strip newline saat iterasi
            def _iterfile(handle: io.TextIOBase) -> Iterator[str]:
                for line in handle:
                    line = line.rstrip("\n\r")
                    if line:
                        yield line
            iters.append(_iterfile(fh))

        merged = heapq.merge(*iters)
        # dedup global saat merge:
        last: Optional[str] = None
        out_lines: List[str] = []
        out_count = 0

        # Tulisan langsung ke file final (untuk menghindari penumpukan memori)
        # tapi tetap atomic melalui temp -> rename
        tmp_fd, tmp_name = tempfile.mkstemp(prefix=".merge_", dir=str(p.parent))
        with os.fdopen(tmp_fd, "wt", encoding="utf-8", newline="\n") as outfh:
            for item in merged:
                if dedup:
                    if last is not None and item == last:
                        continue
                    last = item
                outfh.write(item)
                outfh.write("\n")
                out_count += 1
            if trailing_newline:
                # sudah menulis newline per baris
                pass

        # rename atomic
        os.replace(tmp_name, p)

        return count_in, out_count

    finally:
        # tutup & hapus temp files
        for it in iters:
            try:
                # iterators do not expose file handles directly; handled above
                pass
            except Exception:
                pass
        for f in temp_files:
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass
