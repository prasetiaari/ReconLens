# urls_parser/core/progress.py
from __future__ import annotations

def progress(iterable, desc: str = "", unit: str = ""):
    """
    Wrap iterable dengan tqdm jika tersedia; kalau tidak, kembalikan iterable asli.
    """
    try:
        import sys
        from tqdm import tqdm  # import lokal agar opsional
        return tqdm(iterable, desc=desc, unit=unit, disable=not sys.stderr.isatty())
    except Exception:
        return iterable
