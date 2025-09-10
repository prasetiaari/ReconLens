# urls_parser/modules/sensitive_params.py
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List, Set

from ..core.io_utils import read_nonempty_lines, write_lines_simple, ensure_dir
from ..core.url_utils import parse_url
from ..core.scope import is_in_scope
from ..core.progress import progress



# Nama parameter sensitif (case-insensitive pada nama)
DEFAULT_SENSITIVE_PARAMS: List[str] = [
    "token", "auth", "jwt", "session", "sid", "sso",
    "access_token", "id_token", "refresh_token",
    "api_key", "apikey", "key", "secret", "credential", "password", "pwd",
    "payload", "data",
    "email", "user", "username", "account",
]

def _has_any_param(params: dict[str, list[str]], names: List[str]) -> bool:
    if not params:
        return False
    keys_low = {k.lower() for k in params.keys()}
    for n in names:
        if n.lower() in keys_low:
            return True
    return False

def collect_sensitive_param_urls(
    lines: Iterable[str],
    scope: str,
    include_external: bool = False,
    allow_subdomains: list[str] | None = None,
    deny_subdomains: list[str] | None = None,
    sensitive_param_names: List[str] = DEFAULT_SENSITIVE_PARAMS,
) -> Set[str]:
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
        if _has_any_param(params, sensitive_param_names):
            urls.add(parsed["url_raw"])
    return urls

def run(
    input_path: str,
    output_dir: str,
    scope: str,
    include_external: bool = False,
    allow_subdomains: list[str] | None = None,
    deny_subdomains: list[str] | None = None,
    sensitive_param_names: List[str] = DEFAULT_SENSITIVE_PARAMS,
) -> tuple[int, int]:
    """
    Baca input, scan per-URL dengan progress bar, tulis sensitive_params.txt (dedup + sort).
    Return (count_input_lines, count_urls_written)
    """
    lines = list(read_nonempty_lines(input_path))
    urls: set[str] = set()

    for url in progress(lines, desc="sensitive_params", unit="url"):
        parsed = parse_url(url)
        if not parsed.get("valid"):
            continue

        host = parsed.get("host")
        if not host:
            continue

        if not include_external and not is_in_scope(host, scope, allow_subdomains, deny_subdomains):
            continue

        params = parsed.get("params") or {}
        # nama param sensitif (case-insensitive)
        keys_low = {k.lower() for k in params.keys()}
        if any(n.lower() in keys_low for n in sensitive_param_names):
            urls.add(parsed["url_raw"])

    out_dir = Path(output_dir)
    ensure_dir(out_dir)
    out_file = out_dir / "sensitive_params.txt"
    written = write_lines_simple(out_file, sorted(urls))[1]
    return len(lines), written

# -------- CLI --------

def parse_cli_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract URLs that contain sensitive parameter names (passive)."
    )
    p.add_argument("--scope", required=True)
    p.add_argument("--input", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--include-external", action="store_true")
    p.add_argument("--allow-subdomains", default="")
    p.add_argument("--deny-subdomains", default="")
    p.add_argument("--params", default="", help="Comma-separated extra param names")
    return p.parse_args()

def main() -> None:
    args = parse_cli_args()
    allow = [s.strip() for s in args.allow_subdomains.split(",") if s.strip()]
    deny  = [s.strip() for s in args.deny_subdomains.split(",") if s.strip()]
    extra = [s.strip() for s in args.params.split(",") if s.strip()]
    names = DEFAULT_SENSITIVE_PARAMS + extra
    total_in, total_out = run(
        input_path=args.input,
        output_dir=args.out,
        scope=args.scope,
        include_external=args.include_external,
        allow_subdomains=allow or None,
        deny_subdomains=deny or None,
        sensitive_param_names=names,
    )
    print(f"[sensitive_params] read={total_in}  written_urls={total_out}  -> {Path(args.out)/'sensitive_params.txt'}")

if __name__ == "__main__":
    main()
