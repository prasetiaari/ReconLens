# urls_parser/modules/documents.py
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List, Set

from ..core.io_utils import read_nonempty_lines, write_lines_simple, ensure_dir
from ..core.url_utils import parse_url, get_extension
from ..core.scope import is_in_scope
from ..core.progress import progress


# Ekstensi target (semua lowercase, tanpa titik)
DOC_EXT: List[str] = [
    # dokumen
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    # arsip/backup
    "zip", "rar", "7z", "tar", "tgz", "gz", "bak", "old", "backup",
    # data/konfig
    "csv", "tsv", "json", "ndjson", "xml", "sql", "yaml", "yml", "ini", "conf", "env",
    # kunci/sertifikat
    "pem", "key", "ppk", "cert",
]

def collect_document_urls(
    lines: Iterable[str],
    scope: str,
    include_external: bool = False,
    allow_subdomains: list[str] | None = None,
    deny_subdomains: list[str] | None = None,
    extra_ext: List[str] | None = None,
) -> Set[str]:
    target_ext = set(DOC_EXT + (extra_ext or []))
    urls: Set[str] = set()
    for url in lines:
        parsed = parse_url(url)
        if not parsed.get("valid"):
            continue
        host = parsed["host"]
        if not host:
            continue
        if not include_external and not is_in_scope(host, scope, allow_subdomains, deny_subdomains):
            continue
        ext = get_extension(parsed.get("path") or "")
        if ext and ext.lower() in target_ext:
            urls.add(parsed["url_raw"])
    return urls

def run(
    input_path: str,
    output_dir: str,
    scope: str,
    include_external: bool = False,
    allow_subdomains: list[str] | None = None,
    deny_subdomains: list[str] | None = None,
    extra_ext: List[str] | None = None,
) -> tuple[int, int]:
    """
    Baca input, scan per-URL dengan progress bar, tulis documents.txt (dedup + sort).
    Target ekstensi = DOC_EXT + extra_ext (jika ada).
    Return (count_input_lines, count_urls_written)
    """
    lines = list(read_nonempty_lines(input_path))
    target_ext = set(DOC_EXT + (extra_ext or []))
    urls: set[str] = set()

    for url in progress(lines, desc="documents", unit="url"):
        parsed = parse_url(url)
        if not parsed.get("valid"):
            continue

        host = parsed.get("host")
        if not host:
            continue

        if not include_external and not is_in_scope(host, scope, allow_subdomains, deny_subdomains):
            continue

        ext = get_extension(parsed.get("path") or "")
        if ext and ext.lower() in target_ext:
            urls.add(parsed["url_raw"])

    out_dir = Path(output_dir)
    ensure_dir(out_dir)
    out_file = out_dir / "documents.txt"
    written = write_lines_simple(out_file, sorted(urls))[1]
    return len(lines), written

# -------- CLI --------

def parse_cli_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract document/archive/config/key URLs from gau/waymore results (passive)."
    )
    p.add_argument("--scope", required=True)
    p.add_argument("--input", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--include-external", action="store_true")
    p.add_argument("--allow-subdomains", default="")
    p.add_argument("--deny-subdomains", default="")
    p.add_argument("--extra-ext", default="", help="Comma-separated additional extensions")
    return p.parse_args()

def main() -> None:
    args = parse_cli_args()
    allow = [s.strip() for s in args.allow_subdomains.split(",") if s.strip()]
    deny  = [s.strip() for s in args.deny_subdomains.split(",") if s.strip()]
    extra = [s.strip().lower() for s in args.extra_ext.split(",") if s.strip()]
    total_in, total_out = run(
        input_path=args.input,
        output_dir=args.out,
        scope=args.scope,
        include_external=args.include_exernal if hasattr(args, "include_exernal") else args.include_external,
        allow_subdomains=allow or None,
        deny_subdomains=deny or None,
        extra_ext=extra or None,
    )
    print(f"[documents] read={total_in}  written_urls={total_out}  -> {Path(args.out)/'documents.txt'}")

if __name__ == "__main__":
    main()
