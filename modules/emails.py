# urls_parser/modules/emails.py
from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Iterable, List, Set, Tuple

from ..core.io_utils import read_nonempty_lines, write_lines_simple, ensure_dir
from ..core.url_utils import parse_url
from ..core.scope import is_in_scope
from ..core.progress import progress  # ✅ progress helper

# ============================================================
# 1) Email extraction & filtering rules
# ============================================================

# Email regex dengan anchor "pembatas URL" di kanan
RE_EMAIL = re.compile(
    r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?=$|[/?#&\"' \)\(,;])",
    re.IGNORECASE,
)

# Provider umum: bisa ditambah via --email-domains
COMMON_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.co.id", "outlook.com", "hotmail.com",
    "icloud.com", "proton.me", "protonmail.com", "yandex.com", "zoho.com",
    "aol.com", "live.com", "msn.com", "gmx.com", "mail.com",
}

STATIC_EXT = {
    "png","jpg","jpeg","gif","svg","ico","webp","css","js","map",
    "mp4","webm","mov","avi","mp3","wav","flac","woff","woff2","ttf","otf","eot",
}

def _split_local_domain(email: str) -> Tuple[str, str] | None:
    m = RE_EMAIL.fullmatch(email)
    if not m:
        return None
    return m.group(1), m.group(2).lower()

def _tld_looks_ok(domain: str) -> bool:
    parts = domain.rsplit(".", 1)
    if len(parts) != 2:
        return False
    tld = parts[1]
    return bool(re.fullmatch(r"[A-Za-z]{2,24}", tld))

def _domain_in_scope(email_domain: str, scope: str) -> bool:
    d = email_domain.lower().rstrip(".")
    s = (scope or "").lower().rstrip(".")
    return bool(s and (d == s or d.endswith("." + s)))

def _domain_whitelisted(email_domain: str, scope: str, extra_allow: Set[str]) -> bool:
    d = email_domain.lower()
    return (
        d in COMMON_EMAIL_DOMAINS
        or d in extra_allow
        or _domain_in_scope(d, scope)
    )

def _ext_from_path(path: str) -> str | None:
    if "." not in path:
        return None
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return None
    return name.rsplit(".", 1)[-1].lower()

def _looks_static_path(path: str) -> bool:
    ext = _ext_from_path(path or "")
    return (ext in STATIC_EXT) if ext else False

def _mask_email(e: str) -> str:
    parts = _split_local_domain(e)
    if not parts:
        return e
    local, domain = parts
    if len(local) <= 2:
        masked = local[0] + "*" * max(0, len(local)-1)
    else:
        masked = local[0] + "*" * (len(local)-2) + local[-1]
    return f"{masked}@{domain}"

# ============================================================
# 2) Core collection (dengan progress bar)
# ============================================================

def _extract_emails_from_text(s: str) -> List[str]:
    return [m.group(0) for m in RE_EMAIL.finditer(s or "")]

def collect_email_urls(
    lines: Iterable[str],
    scope: str,
    include_external: bool = False,
    allow_subdomains: List[str] | None = None,
    deny_subdomains: List[str] | None = None,
    extra_email_domains: Set[str] | None = None,
    scan_path: bool = False,
) -> Tuple[Set[str], Set[str]]:
    """
    Kembalikan:
      - set_urls: URL penuh yang mengandung email "valid"
      - set_emails: daftar email "valid" (dipakai jika --emit-raw-emails)
    'Valid' = lulus whitelist domain (provider umum / extra / in-scope) dan TLD heuristik.
    Default scan hanya query & fragment; path opsional agar terhindar dari '@2x.png'.
    """
    urls_out: Set[str] = set()
    emails_out: Set[str] = set()
    extra_allow = {d.strip().lower() for d in (extra_email_domains or set()) if d.strip()}

    # ✅ Progress bar per-URL
    for url in progress(lines, desc="emails", unit="url"):
        parsed = parse_url(url)
        if not parsed.get("valid"):
            continue
        host = parsed.get("host")
        if not host:
            continue
        if not include_external and not is_in_scope(host, scope, allow_subdomains, deny_subdomains):
            continue

        found_any = False

        # 1) query param values
        params = parsed.get("params") or {}
        for vs in params.values():
            for v in vs:
                for e in _extract_emails_from_text(v):
                    parts = _split_local_domain(e)
                    if not parts:
                        continue
                    _, domain = parts
                    if not _tld_looks_ok(domain):
                        continue
                    if not _domain_whitelisted(domain, scope, extra_allow):
                        continue
                    emails_out.add(e)
                    found_any = True

        # 2) fragment
        frag = parsed.get("fragment") or ""
        for e in _extract_emails_from_text(frag):
            parts = _split_local_domain(e)
            if not parts:
                continue
            _, domain = parts
            if not _tld_looks_ok(domain):
                continue
            if not _domain_whitelisted(domain, scope, extra_allow):
                continue
            emails_out.add(e)
            found_any = True

        # 3) path (opsional; default off untuk menghindari false positive @2x.png)
        if scan_path:
            path = parsed.get("path") or ""
            if not _looks_static_path(path):  # skip assets
                for e in _extract_emails_from_text(path):
                    parts = _split_local_domain(e)
                    if not parts:
                        continue
                    local, domain = parts
                    # hindari retina-style "icon@2x.png"
                    if local.lower().endswith(("@2x", "@3x")) or local.lower().endswith(("2x", "3x")):
                        continue
                    if not _tld_looks_ok(domain):
                        continue
                    if not _domain_whitelisted(domain, scope, extra_allow):
                        continue
                    emails_out.add(e)
                    found_any = True

        if found_any:
            urls_out.add(parsed["url_raw"])

    return urls_out, emails_out

# ============================================================
# 3) Public API & CLI
# ============================================================

def run(
    input_path: str,
    output_dir: str,
    scope: str,
    include_external: bool = False,
    allow_subdomains: List[str] | None = None,
    deny_subdomains: List[str] | None = None,
    email_domains: List[str] | None = None,
    scan_path: bool = False,
    emit_raw_emails: bool = False,
    mask_emails: bool = False,
) -> tuple[int, int]:
    """
    Tulis:
      - emails_urls.txt : URL penuh yang mengandung email valid
      - (opsional) emails_found.txt : list email (boleh dimask)
    Return (count_input_lines, count_urls_written)
    """
    lines_list = list(read_nonempty_lines(input_path))
    urls, emails = collect_email_urls(
        lines_list,
        scope=scope,
        include_external=include_external,
        allow_subdomains=allow_subdomains,
        deny_subdomains=deny_subdomains,
        extra_email_domains=set(email_domains or []),
        scan_path=scan_path,
    )

    out_dir = Path(output_dir)
    ensure_dir(out_dir)
    urls_file = out_dir / "emails_urls.txt"
    _, written_urls = write_lines_simple(urls_file, sorted(urls))

    if emit_raw_emails:
        emails_file = out_dir / "emails_found.txt"
        if mask_emails:
            masked = (_mask_email(e) for e in emails)
            write_lines_simple(emails_file, sorted(set(masked)))
        else:
            write_lines_simple(emails_file, sorted(emails))

    return len(lines_list), written_urls

# -------- CLI --------

def parse_cli_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract email-related intel: output URLs containing emails (whitelisted providers + in-scope)."
    )
    p.add_argument("--scope", required=True, help="Root domain, e.g. example.com")
    p.add_argument("--input", required=True, help="Input file (txt or .gz) with URLs")
    p.add_argument("--out", required=True, help="Output directory for this scope")
    p.add_argument("--include-external", action="store_true", help="Include hosts outside the root scope")
    p.add_argument("--allow-subdomains", default="", help="Comma-separated glob list")
    p.add_argument("--deny-subdomains", default="", help="Comma-separated glob list")
    p.add_argument("--email-domains", default="", help="Comma-separated extra allowed email domains (besides common providers + scope)")
    p.add_argument("--scan-path", action="store_true", help="Also scan path segments (default off to avoid @2x.png false positives)")
    p.add_argument("--emit-raw-emails", action="store_true", help="Also write raw emails to emails_found.txt")
    p.add_argument("--mask-emails", action="store_true", help="Mask raw emails in emails_found.txt")
    return p.parse_args()

def main() -> None:
    args = parse_cli_args()
    allow = [s.strip() for s in args.allow_subdomains.split(",") if s.strip()]
    deny  = [s.strip() for s in args.deny_subdomains.split(",") if s.strip()]
    extra = [s.strip().lower() for s in args.email_domains.split(",") if s.strip()]
    total_in, total_out = run(
        input_path=args.input,
        output_dir=args.out,
        scope=args.scope,
        include_external=args.include_external,
        allow_subdomains=allow or None,
        deny_subdomains=deny or None,
        email_domains=extra or None,
        scan_path=args.scan_path,
        emit_raw_emails=args.emit_raw_emails,
        mask_emails=args.mask_emails,
    )
    print(f"[emails] read={total_in}  urls_with_emails={total_out}  -> {Path(args.out)/'emails_urls.txt'}")
    if args.emit_raw_emails:
        print(f"[emails] raw emails -> {Path(args.out)/'emails_found.txt'}")

if __name__ == "__main__":
    main()
