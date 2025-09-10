# urls_parser/modules/params.py
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List, Set, Tuple

from ..core.io_utils import read_nonempty_lines, write_lines_simple, ensure_dir
from ..core.url_utils import parse_url
from ..core.scope import is_in_scope
from ..core.progress import progress

# Param umum yang sering jadi noise; bisa ditambah via --exclude
DEFAULT_EXCLUDES: List[str] = [
    "_", "__", "cb", "v", "ver", "ref",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid",
]

def collect_params_and_urls(
    lines: Iterable[str],
    scope: str,
    include_external: bool = False,
    allow_subdomains: List[str] | None = None,
    deny_subdomains: List[str] | None = None,
    min_len: int = 1,
    exclude: List[str] | None = None,
    lowercase: bool = True,
) -> Tuple[Set[str], Set[str]]:
    """
    Kembalikan:
      - set_names: nama parameter unik (sesuai filter)
      - set_urls: URL penuh yang mengandung ≥1 parameter yang lolos filter
    """
    excludes = {(e.lower() if lowercase else e) for e in (exclude or [])}
    set_names: Set[str] = set()
    set_urls: Set[str] = set()

    for url in progress(lines, desc="params", unit="url"):
        parsed = parse_url(url)
        if not parsed.get("valid"):
            continue
        host = parsed.get("host")
        if not host:
            continue
        if not include_external and not is_in_scope(host, scope, allow_subdomains, deny_subdomains):
            continue

        q = parsed.get("params") or {}
        if not q:
            continue

        matched_any = False
        for name in q.keys():
            n = name.strip()
            if not n:
                continue
            n2 = n.lower() if lowercase else n
            if len(n2) < min_len:
                continue
            if n2 in excludes:
                continue

            set_names.add(n2)
            matched_any = True

        if matched_any:
            set_urls.add(parsed["url_raw"])

    return set_names, set_urls

def run(
    input_path: str,
    output_dir: str,
    scope: str,
    include_external: bool = False,
    allow_subdomains: List[str] | None = None,
    deny_subdomains: List[str] | None = None,
    min_len: int = 1,
    exclude: List[str] | None = None,
    lowercase: bool = True,
) -> tuple[int, int]:
    """
    Tulis:
      - params.txt       : nama parameter unik
      - params_urls.txt  : URL yang mengandung minimal satu parameter lolos filter
    Return (count_input_lines, count_params_written)
    """
    lines_list = list(read_nonempty_lines(input_path))
    names, urls = collect_params_and_urls(
        lines_list,
        scope=scope,
        include_external=include_external,
        allow_subdomains=allow_subdomains,
        deny_subdomains=deny_subdomains,
        min_len=min_len,
        exclude=exclude,
        lowercase=lowercase,
    )

    out_dir = Path(output_dir)
    ensure_dir(out_dir)

    names_file = out_dir / "params.txt"
    urls_file  = out_dir / "params_urls.txt"

    _, written_names = write_lines_simple(names_file, sorted(names))
    write_lines_simple(urls_file, sorted(urls))

    return len(lines_list), written_names

# -------- CLI --------

def parse_cli_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Collect unique query parameter names and the URLs that contain them."
    )
    p.add_argument("--scope", required=True, help="Root domain, e.g. example.com")
    p.add_argument("--input", required=True, help="Input file (txt or .gz) with URLs")
    p.add_argument("--out", required=True, help="Output directory for this scope")

    # scoping
    p.add_argument("--include-external", action="store_true",
                   help="Include hosts outside the root scope as well")
    p.add_argument("--allow-subdomains", default="",
                   help="Comma-separated glob allow list (e.g. '*.api.example.com,admin.example.com')")
    p.add_argument("--deny-subdomains", default="",
                   help="Comma-separated glob deny list")

    # filtering
    p.add_argument("--min-len", type=int, default=1,
                   help="Minimum parameter name length (default: 1)")
    p.add_argument("--exclude", default="",
                   help="Comma-separated param names to exclude, case-insensitive")
    p.add_argument("--no-lowercase", action="store_true",
                   help="Keep original case (default lowers all names)")

    return p.parse_args()

def main() -> None:
    args = parse_cli_args()
    allow = [s.strip() for s in args.allow_subdomains.split(",") if s.strip()]
    deny  = [s.strip() for s in args.deny_subdomains.split(",") if s.strip()]
    excl  = list({*DEFAULT_EXCLUDES, *[s.strip() for s in args.exclude.split(",") if s.strip()]})

    total_in, total_out = run(
        input_path=args.input,
        output_dir=args.out,
        scope=args.scope,
        include_external=args.include_external,
        allow_subdomains=allow or None,
        deny_subdomains=deny or None,
        min_len=args.min_len,
        exclude=excl,
        lowercase=not args.no_lowercase,
    )
    out = Path(args.out)
    print(f"[params] read={total_in}  written_names={total_out}  -> {out/'params.txt'}")
    print(f"[params] urls -> {out/'params_urls.txt'}")

if __name__ == "__main__":
    main()
