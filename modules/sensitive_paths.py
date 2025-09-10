# urls_parser/modules/sensitive_paths.py
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List, Set

from ..core.io_utils import read_nonempty_lines, write_lines_simple, ensure_dir
from ..core.url_utils import parse_url, is_static_asset
from ..core.scope import is_in_scope
from ..core.progress import progress


# --- daftar pola sensitif (bisa dikembangkan dari config/paths.yaml) ---
DEFAULT_PATTERNS: List[str] = [
    "/admin", "/admin/", "/administrator",
    "/panel", "/panel/", "/controlpanel", "/cp",
    "/dashboard", "/manage", "/management", "/backend",
    "/internal", "/console",
    "/login", "/signin", "/logon", "/user/login", "/users/sign_in",
    "/wp-admin/", "/wp-login.php", "/wp-json/",
    "/phpmyadmin", "/phpmyadmin/", "/adminer", "/adminer.php",
    "/swagger", "/swagger-ui", "/swagger.json", "/openapi.json",
    "/graphql", "/graphiql", "/playground",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/loggers",
    "/jenkins", "/jenkins/", "/script", "/scriptText",
    "/grafana", "/grafana/login", "/prometheus", "/metrics",
    "/kibana", "/_plugin/kibana", "/_cat/indices", "/_cluster/health",
]

def collect_sensitive_paths(
    lines: Iterable[str],
    scope: str,
    include_external: bool = False,
    allow_subdomains: list[str] | None = None,
    deny_subdomains: list[str] | None = None,
    patterns: List[str] = DEFAULT_PATTERNS,
) -> Set[str]:
    """
    Cari URL yang path-nya mengandung pola sensitif.
    - Scope di-filter kecuali include_external=True
    - Skip static assets
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
        if is_static_asset(parsed["path"] or ""):
            continue
        path_low = (parsed["path"] or "").lower()
        for pat in patterns:
            if pat.lower() in path_low:
                urls.add(parsed["url_raw"])
                break
    return urls

def run(
    input_path: str,
    output_dir: str,
    scope: str,
    include_external: bool = False,
    allow_subdomains: list[str] | None = None,
    deny_subdomains: list[str] | None = None,
    patterns: List[str] = DEFAULT_PATTERNS,
) -> tuple[int, int]:
    """
    Baca input, scan per-URL dengan progress bar, tulis sensitive_paths.txt (dedup + sort).
    Return (count_input_lines, count_urls_written)
    """
    lines = list(read_nonempty_lines(input_path))
    urls: set[str] = set()

    # ✅ progress per modul
    for url in progress(lines, desc="sensitive_paths", unit="url"):
        parsed = parse_url(url)
        if not parsed.get("valid"):
            continue

        host = parsed.get("host")
        if not host:
            continue

        if not include_external and not is_in_scope(host, scope, allow_subdomains, deny_subdomains):
            continue

        # skip static assets (js/css/img) biar nggak noisy
        if is_static_asset(parsed.get("path") or ""):
            continue

        path_low = (parsed.get("path") or "").lower()
        for pat in patterns:
            if pat.lower() in path_low:
                urls.add(parsed["url_raw"])
                break

    out_dir = Path(output_dir)
    ensure_dir(out_dir)
    out_file = out_dir / "sensitive_paths.txt"
    written = write_lines_simple(out_file, sorted(urls))[1]
    return len(lines), written

# -------- CLI standalone --------

def parse_cli_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract sensitive paths from gau/waymore URLs (passive)."
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
        help="Comma-separated glob list"
    )
    p.add_argument(
        "--deny-subdomains",
        default="",
        help="Comma-separated glob list"
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
    print(f"[sensitive_paths] read={total_in}  written_urls={total_out}  -> {Path(args.out)/'sensitive_paths.txt'}")

if __name__ == "__main__":
    main()
