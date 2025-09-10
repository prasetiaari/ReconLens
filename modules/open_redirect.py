# urls_parser/modules/open_redirect.py
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List, Set

from ..core.io_utils import read_nonempty_lines, write_lines_simple, ensure_dir
from ..core.url_utils import parse_url
from ..core.scope import is_in_scope
from ..core.progress import progress


# Nama parameter yang sering dipakai untuk redirect (case-insensitive match pada nama)
DEFAULT_PARAMS: List[str] = [
    "url", "next", "redirect", "return", "continue", "callback",
    "dest", "destination", "target", "go", "link", "to", "redir",
    "returnurl", "service", "u", "ru", "ref", "site", "path",
]

def _looks_offsite_value(val: str) -> bool:
    """
    Heuristik nilai param yang mengarah ke offsite/redirect:
    - absolute URL http(s)://
    - schemeless //host
    - encoded double slash %2f%2f (lowercase)
    """
    v = (val or "").strip()
    if not v:
        return False
    lv = v.lower()
    return (
        lv.startswith("http://")
        or lv.startswith("https://")
        or lv.startswith("//")
        or "%2f%2f" in lv  # encoded //
    )

def _has_redirect_param(params: dict[str, list[str]], names: List[str]) -> bool:
    if not params:
        return False
    keys_low = {k.lower() for k in params.keys()}
    for n in names:
        if n.lower() in keys_low:
            return True
    return False

def _any_value_offsite(params: dict[str, list[str]], names: List[str]) -> bool:
    for n in names:
        vals = params.get(n) or params.get(n.lower())
        if not vals:
            # fallback: scan case-insensitively
            for k, vs in params.items():
                if k.lower() == n.lower():
                    vals = vs
                    break
        if not vals:
            continue
        for v in vals:
            if _looks_offsite_value(v):
                return True
    return False

def collect_open_redirect_urls(
    lines: Iterable[str],
    scope: str,
    include_external: bool = False,
    allow_subdomains: list[str] | None = None,
    deny_subdomains: list[str] | None = None,
    param_names: List[str] = DEFAULT_PARAMS,
    only_offsite_values: bool = False,
) -> Set[str]:
    """
    Ambil URL yang punya parameter redirect-prone.
    - only_offsite_values=True → tulis hanya jika nilai param terlihat mengarah ke offsite (http://, https://, //, %2f%2f).
    - include_external=False → hanya host in-scope yang dipertimbangkan.
    """
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

        params = parsed.get("params") or {}
        if not _has_redirect_param(params, param_names):
            continue

        if only_offsite_values and not _any_value_offsite(params, param_names):
            # skip kalau diminta hanya yang valuenya offsite dan tidak memenuhi
            continue

        urls.add(parsed["url_raw"])
    return urls

def run(
    input_path: str,
    output_dir: str,
    scope: str,
    include_external: bool = False,
    allow_subdomains: list[str] | None = None,
    deny_subdomains: list[str] | None = None,
    param_names: List[str] = DEFAULT_PARAMS,
    only_offsite_values: bool = False,
) -> tuple[int, int]:
    """
    Baca input, scan per-URL dengan progress bar, tulis open_redirect_candidates.txt (dedup + sort).
    Return (count_input_lines, count_urls_written)
    """
    lines = list(read_nonempty_lines(input_path))
    urls: set[str] = set()

    for url in progress(lines, desc="open_redirect", unit="url"):
        parsed = parse_url(url)
        if not parsed.get("valid"):
            continue

        host = parsed.get("host")
        if not host:
            continue

        if not include_external and not is_in_scope(host, scope, allow_subdomains, deny_subdomains):
            continue

        params = parsed.get("params") or {}
        if not _has_redirect_param(params, param_names):
            continue

        if only_offsite_values and not _any_value_offsite(params, param_names):
            continue

        urls.add(parsed["url_raw"])

    out_dir = Path(output_dir)
    ensure_dir(out_dir)
    out_file = out_dir / "open_redirect_candidates.txt"
    written = write_lines_simple(out_file, sorted(urls))[1]
    return len(lines), written

# -------- CLI standalone --------

def parse_cli_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract open-redirect candidate URLs from gau/waymore results (passive)."
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
    p.add_argument(
        "--only-offsite-values",
        action="store_true",
        help="If set, only keep URLs whose redirect param value looks offsite (http(s)://, //, %2f%2f).",
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
        only_offsite_values=args.only_offsite_values,
    )
    print(f"[open_redirect] read={total_in}  written_urls={total_out}  -> {Path(args.out)/'open_redirect_candidates.txt'}")

if __name__ == "__main__":
    main()
