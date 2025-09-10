# urls_parser/modules/jwt_candidates.py
from __future__ import annotations

import argparse
import base64
import json
import re
from pathlib import Path
from typing import Iterable, Set

from ..core.io_utils import read_nonempty_lines, write_lines_simple, ensure_dir
from ..core.url_utils import parse_url, decode_percent_once, is_static_asset
from ..core.scope import is_in_scope
from ..core.progress import progress

# ----------------------
# Regex kandidat JWT (longgar, validasi ketat di tahap berikut)
# ----------------------
B64URL = r"[A-Za-z0-9_-]"
SEG = rf"{B64URL}{{4,}}"  # minimal 4 agar decode masuk akal

RE_JWS3 = re.compile(rf"({SEG})\.({SEG})\.({SEG})")                           # header.payload.signature
RE_JWS2 = re.compile(rf"({SEG})\.({SEG})")                                     # header.payload (unsigned)
RE_JWE5 = re.compile(rf"({SEG})\.({SEG})\.({SEG})\.({SEG})\.({SEG})")          # header.encryptedKey.iv.ciphertext.tag

DOT_ENC_LOWER = "%2e"
DOT_ENC_UPPER = "%2E"

# ----------------------
# Helper base64url & header check
# ----------------------

def _b64url_decode_safe(s: str) -> bytes | None:
    try:
        pad = (-len(s)) % 4
        return base64.urlsafe_b64decode(s + ("=" * pad))
    except Exception:
        return None

def _is_jwt_header(seg: str) -> bool:
    """
    True kalau segmen pertama bisa di-decode ke JSON dan mengandung kunci 'alg'.
    Ini memotong false positive seperti 'jquery.cycle.all.latest'.
    """
    raw = _b64url_decode_safe(seg)
    if not raw:
        return False
    try:
        obj = json.loads(raw.decode("utf-8"))
        return isinstance(obj, dict) and "alg" in obj
    except Exception:
        return False

# ----------------------
# Validator kandidat (ketat)
# ----------------------

def _validate_candidate(s: str) -> bool:
    # 5 bagian (JWE)
    m5 = RE_JWE5.search(s)
    if m5 and _is_jwt_header(m5.group(1)):
        return True
    # 3 bagian (JWS)
    m3 = RE_JWS3.search(s)
    if m3 and _is_jwt_header(m3.group(1)):
        return True
    # 2 bagian (unsigned)
    m2 = RE_JWS2.search(s)
    if m2 and _is_jwt_header(m2.group(1)):
        return True
    return False

def _normalize_and_check(s: str) -> bool:
    # coba apa adanya
    if _validate_candidate(s):
        return True
    # ganti %2E -> '.' lalu cek lagi
    s2 = s.replace(DOT_ENC_LOWER, ".").replace(DOT_ENC_UPPER, ".")
    if s2 != s and _validate_candidate(s2):
        return True
    # percent-decode sekali (untuk kasus encoded)
    if "%" in s:
        s3 = decode_percent_once(s)
        if s3 != s and _validate_candidate(s3):
            return True
    return False

# ----------------------
# Ekstraksi candidate strings dari URL terparse
# ----------------------

def _candidate_strings_from_parsed(parsed: dict) -> list[str]:
    cands: list[str] = []

    # 1) Query param values (sudah di-decode parse_qsl)
    for vs in (parsed.get("params") or {}).values():
        for v in vs:
            if v:
                cands.append(v)

    # 2) Path: pecah per-segmen; ambil juga nilai setelah '=' untuk kasus '.../token=eyJ...'
    path = parsed.get("path") or ""
    if path:
        segs = [s for s in path.split("/") if s]
        for s in segs:
            cands.append(s)  # seluruh segmen
            if "=" in s:
                right = s.split("=", 1)[1]
                if right:
                    cands.append(right)

    # 3) Fragment: raw + value setelah '=' jika ada
    frag = parsed.get("fragment") or ""
    if frag:
        cands.append(frag)
        if "=" in frag:
            cands.append(frag.split("=", 1)[1])

    # 4) Raw URL (cadangan; bisa berisi encoded dot/percent)
    url_raw = parsed.get("url_raw") or ""
    if url_raw:
        cands.append(url_raw)

    # Normalisasi ringan untuk setiap kandidat
    normed: list[str] = []
    for s in cands:
        if not s:
            continue
        normed.append(s)
        s2 = s.replace(DOT_ENC_LOWER, ".").replace(DOT_ENC_UPPER, ".")
        if s2 != s:
            normed.append(s2)
        if "%" in s:
            s3 = decode_percent_once(s)
            if s3 != s:
                normed.append(s3)
    return normed

# ----------------------
# Core: deteksi JWT dalam satu URL terparse
# ----------------------

def _any_jwt_in_parsed(parsed: dict) -> bool:
    # Jika path jelas static asset (js/css/png/dll), kecil peluang JWT legit di path itu.
    # Namun jangan langsung return False: JWT bisa muncul di query/fragment.
    static_path = is_static_asset(parsed.get("path") or "")

    # Periksa seluruh kandidat string
    for s in _candidate_strings_from_parsed(parsed):
        # Sedikit optimisasi: kalau kandidat berasal dari path dan static_path True
        # (mis. .js/.css/.png), kita bisa abaikan kandidat yang == path segment penuh,
        # tapi tetap cek query/fragment/param.
        if static_path and s == (parsed.get("path") or ""):
            continue
        if _normalize_and_check(s):
            return True
    return False

# ----------------------
# API modul
# ----------------------

def collect_jwt_urls(
    lines: Iterable[str],
    scope: str,
    include_external: bool = False,
    allow_subdomains: list[str] | None = None,
    deny_subdomains: list[str] | None = None,
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
        if _any_jwt_in_parsed(parsed):
            urls.add(parsed["url_raw"])
    return urls

def run(
    input_path: str,
    output_dir: str,
    scope: str,
    include_external: bool = False,
    allow_subdomains: list[str] | None = None,
    deny_subdomains: list[str] | None = None,
) -> tuple[int, int]:
    """
    Baca input, scan per-URL dengan progress bar, tulis jwt_candidates.txt (dedup + sort).
    Return (count_input_lines, count_urls_written)
    """
    lines = list(read_nonempty_lines(input_path))
    urls: set[str] = set()

    for url in progress(lines, desc="jwt_candidates", unit="url"):
        parsed = parse_url(url)
        if not parsed.get("valid"):
            continue

        host = parsed.get("host")
        if not host:
            continue

        if not include_external and not is_in_scope(host, scope, allow_subdomains, deny_subdomains):
            continue

        if _any_jwt_in_parsed(parsed):
            urls.add(parsed["url_raw"])

    out_dir = Path(output_dir)
    ensure_dir(out_dir)
    out_file = out_dir / "jwt_candidates.txt"
    written = write_lines_simple(out_file, sorted(urls))[1]
    return len(lines), written

# ----------------------
# CLI
# ----------------------

def parse_cli_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract JWT-like tokens from gau/waymore URLs (passive, strict header validation)."
    )
    p.add_argument("--scope", required=True)
    p.add_argument("--input", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--include-external", action="store_true")
    p.add_argument("--allow-subdomains", default="")
    p.add_argument("--deny-subdomains", default="")
    return p.parse_args()

def main() -> None:
    args = parse_cli_args()
    allow = [s.strip() for s in args.allow_subdomains.split(",") if s.strip()]
    deny  = [s.strip() for s in args.deny_subdomains.split(",") if s.strip()]
    total_in, total_out = run(
        input_path=args.input,
        output_dir=args.out,
        scope=args.scope,
        include_external=args.include_external,
        allow_subdomains=allow or None,
        deny_subdomains=deny or None,
    )
    print(f"[jwt_candidates] read={total_in}  written_urls={total_out}  -> {Path(args.out)/'jwt_candidates.txt'}")

if __name__ == "__main__":
    main()
