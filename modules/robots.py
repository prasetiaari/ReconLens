# urls_parser/modules/robots.py
from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Iterable, List, Set, Tuple, Optional

from ..core.io_utils import read_nonempty_lines, write_lines_simple, ensure_dir
from ..core.url_utils import parse_url
from ..core.scope import is_in_scope
from ..core.progress import progress

# ---------------------------------------
# 1) Kumpulkan URL robots.txt (pasif)
# ---------------------------------------

def _is_robots_path(path: str | None) -> bool:
    if not path:
        return False
    # typical forms:
    # /robots.txt , //robots.txt (setelah normalisasi path tetap 1 slash di depan)
    p = path.lower()
    return p.endswith("/robots.txt") or p == "/robots.txt"

def collect_robots_urls(
    lines: Iterable[str],
    scope: str,
    include_external: bool = False,
    allow_subdomains: List[str] | None = None,
    deny_subdomains: List[str] | None = None,
) -> Set[str]:
    """
    Ambil semua URL yang berujung robots.txt
    """
    urls: Set[str] = set()
    for url in lines:
        parsed = parse_url(url)
        if not parsed.get("valid"):
            continue
        host = parsed.get("host")
        if not host:
            continue
        if not include_external and not is_in_scope(host, scope, allow_subdomains, deny_subdomains):
            continue
        if _is_robots_path(parsed.get("path")):
            urls.add(parsed["url_raw"])
    return urls

# ---------------------------------------
# 2) (Opsional) Parse Disallow dari konten robots lokal
# ---------------------------------------
# Mode ini tidak melakukan fetch.
# Kamu bisa sediakan folder berisi file-file robots.txt (mis: hasil download manual).
# Konvensi nama file yang dikenali: 
#   <host>.robots.txt  atau  <host>_robots.txt
#   contoh: www.example.com.robots.txt

RE_DIRECTIVE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*?)\s*$")

def _discover_robots_file_for_host(robots_dir: Path, host: str) -> Optional[Path]:
    """
    Cari file konten robots untuk host.
    Prioritas nama:
      <host>.robots.txt
      <host>_robots.txt
    """
    cand1 = robots_dir / f"{host}.robots.txt"
    if cand1.exists():
        return cand1
    cand2 = robots_dir / f"{host}_robots.txt"
    if cand2.exists():
        return cand2
    return None

def _parse_disallow_lines(text: str) -> List[str]:
    """
    Ambil baris Disallow (dan normalisasi ke path absolut).
    Hanya ekstrak path, abaikan user-agent scoping (pasif wordlist).
    """
    out: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = RE_DIRECTIVE.match(line)
        if not m:
            continue
        key, value = m.group(1).lower(), m.group(2).strip()
        if key != "disallow":
            continue
        # Kosong artinya allow all; skip
        if not value:
            continue
        # normalisasi: pastikan diawali '/'
        if not value.startswith("/"):
            value = "/" + value
        # hapus * anchor di ujung yang kadang dipakai vendor (opsional)
        out.append(value)
    return out

def collect_disallow_from_local(
    robots_urls: Iterable[str],
    robots_dir: str,
) -> Set[str]:
    """
    Dari daftar robots URL, temukan file konten berdasarkan host dan ekstrak Disallow.
    Tidak uniq per-host; semua digabung jadi wordlist global.
    """
    base = Path(robots_dir)
    disallows: Set[str] = set()
    for robots_url in robots_urls:
        parsed = parse_url(robots_url)
        if not parsed.get("valid"):
            continue
        host = parsed.get("host") or ""
        if not host:
            continue
        f = _discover_robots_file_for_host(base, host)
        if not f:
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        items = _parse_disallow_lines(text)
        for it in items:
            disallows.add(it)
    return disallows

# ---------------------------------------
# 3) API modul + CLI
# ---------------------------------------

def run(
    input_path: str,
    output_dir: str,
    scope: str,
    include_external: bool = False,
    allow_subdomains: List[str] | None = None,
    deny_subdomains: List[str] | None = None,
    robots_dir: str | None = None,      # folder optional utk konten robots
    write_disallow: bool = True,
) -> Tuple[int, int]:
    """
    Baca input, scan per-URL dengan progress bar.
    Tulis:
      - robots_urls.txt  (selalu)
      - robots_disallow.txt (opsional; hanya jika robots_dir disediakan & ditemukan file)
    Return (count_input_lines, count_urls_written)
    """
    lines = list(read_nonempty_lines(input_path))
    urls: Set[str] = set()

    # ✅ progress per modul
    for url in progress(lines, desc="robots", unit="url"):
        parsed = parse_url(url)
        if not parsed.get("valid"):
            continue
        host = parsed.get("host")
        if not host:
            continue
        if not include_external and not is_in_scope(host, scope, allow_subdomains, deny_subdomains):
            continue
        if _is_robots_path(parsed.get("path")):
            urls.add(parsed["url_raw"])

    out_dir = Path(output_dir)
    ensure_dir(out_dir)
    urls_file = out_dir / "robots_urls.txt"
    _, written_urls = write_lines_simple(urls_file, sorted(urls))

    # Opsional: parse Disallow dari file konten lokal
    if robots_dir and write_disallow:
        disallows = collect_disallow_from_local(urls, robots_dir=robots_dir)
        dis_file = out_dir / "robots_disallow.txt"
        write_lines_simple(dis_file, sorted(disallows))

    return len(lines), written_urls

# -------- CLI --------

def parse_cli_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Collect robots.txt URLs (passive). Optionally parse Disallow from local robots folder."
    )
    p.add_argument("--scope", required=True, help="Root domain, e.g. example.com")
    p.add_argument("--input", required=True, help="Input file (txt or .gz) with URLs")
    p.add_argument("--out", required=True, help="Output directory for this scope")
    p.add_argument("--include-external", action="store_true", help="Include hosts outside the root scope")
    p.add_argument("--allow-subdomains", default="", help="Comma-separated glob list")
    p.add_argument("--deny-subdomains", default="", help="Comma-separated glob list")
    p.add_argument("--robots-dir", default="", help="Directory containing local robots contents (e.g. www.example.com.robots.txt)")
    p.add_argument("--no-disallow", action="store_true", help="Do not write robots_disallow.txt even if robots-dir provided")
    return p.parse_args()

def main() -> None:
    args = parse_cli_args()
    allow = [s.strip() for s in args.allow_subdomains.split(",") if s.strip()]
    deny  = [s.strip() for s in args.deny_subdomains.split(",") if s.strip()]
    robots_dir = args.robots_dir.strip() or None
    total_in, total_out = run(
        input_path=args.input,
        output_dir=args.out,
        scope=args.scope,
        include_external=args.include_external,
        allow_subdomains=allow or None,
        deny_subdomains=deny or None,
        robots_dir=robots_dir,
        write_disallow=not args.no_disallow,
    )
    out = Path(args.out)
    print(f"[robots] read={total_in}  robots_urls={total_out}  -> {out/'robots_urls.txt'}")
    if robots_dir and not args.no_disallow:
        # tidak ada angka yang kita cetak untuk disallow karena tergantung file lokal yang berhasil ditemukan
        print(f"[robots] disallow (if any) -> {out/'robots_disallow.txt'}")

if __name__ == "__main__":
    main()
