# urls_parser/modules/subdomains.py
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, Set

from ..core.io_utils import read_nonempty_lines, write_lines_simple, ensure_dir
from ..core.url_utils import parse_url
from ..core.scope import is_in_scope
from ..core.progress import progress


def collect_subdomains(
    lines: Iterable[str],
    scope: str,
    include_external: bool = False,
    allow_subdomains: list[str] | None = None,
    deny_subdomains: list[str] | None = None,
) -> Set[str]:
    """
    Kumpulkan host unik dari daftar URL.
    - Jika include_external=False → hanya host in-scope.
    - Jika True → semua host (tetap bisa disaring allow/deny jika diberikan).
    """
    hosts: Set[str] = set()
    for url in lines:
        parsed = parse_url(url)
        if not parsed.get("valid"):
            continue
        host = parsed["host"]
        if not host:
            continue
        if include_external:
            if allow_subdomains or deny_subdomains:
                # Jika user tetap memberi allow/deny, hormati itu
                if is_in_scope(host, scope, allow_subdomains, deny_subdomains):
                    hosts.add(host)
                else:
                    hosts.add(host)  # eksternal pun tetap dimasukkan
            else:
                hosts.add(host)
        else:
            if is_in_scope(host, scope, allow_subdomains, deny_subdomains):
                hosts.add(host)
    return hosts

def run(
    input_path: str,
    output_dir: str,
    scope: str,
    include_external: bool = False,
    allow_subdomains: list[str] | None = None,
    deny_subdomains: list[str] | None = None,
) -> tuple[int, int]:
    """
    Baca file input (gau/waymore), loop per-URL dengan progress bar, tulis subdomains.txt.
    """
    lines = list(read_nonempty_lines(input_path))
    hosts = set()

    # ✅ progress per-modul
    for url in progress(lines, desc="subdomains", unit="url"):
        parsed = parse_url(url)
        if not parsed.get("valid"):
            continue
        host = parsed["host"]
        if not host:
            continue
        if include_external or is_in_scope(host, scope, allow_subdomains, deny_subdomains):
            hosts.add(host)

    out_dir = Path(output_dir)
    ensure_dir(out_dir)
    out_file = out_dir / "subdomains.txt"
    written = write_lines_simple(out_file, sorted(hosts))[1]
    return len(lines), written

# -------- CLI standalone untuk modul ini --------

def parse_cli_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract unique subdomains from gau/waymore URLs (passive)."
    )
    p.add_argument("--scope", required=True, help="Root domain, e.g. example.com")
    p.add_argument("--input", required=True, help="Input file (txt or .gz) with URLs")
    p.add_argument("--out", required=True, help="Output directory for this scope")
    p.add_argument(
        "--include-external",
        action="store_true",
        help="Include hosts outside the root scope as well",
    )
    p.add_argument(
        "--allow-subdomains",
        default="",
        help="Comma-separated glob list (e.g. '*.api.example.com,admin.example.com')",
    )
    p.add_argument(
        "--deny-subdomains",
        default="",
        help="Comma-separated glob list to exclude (e.g. 'cdn.example.com,static.*')",
    )
    return p.parse_args()

def main() -> None:
    args = parse_cli_args()
    allow = [s.strip() for s in args.allow_subdomains.split(",") if s.strip()]
    deny = [s.strip() for s in args.deny_subdomains.split(",") if s.strip()]
    total_in, total_out = run(
        input_path=args.input,
        output_dir=args.out,
        scope=args.scope,
        include_external=args.include_external,
        allow_subdomains=allow or None,
        deny_subdomains=deny or None,
    )
    print(f"[subdomains] read={total_in}  written_unique_hosts={total_out}  -> {Path(args.out)/'subdomains.txt'}")

if __name__ == "__main__":
    main()
