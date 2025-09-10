# urls_parser/__main__.py
from __future__ import annotations
import argparse
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Progress bar optional (tqdm). Fallback akan tetap jalan tanpa bar.
try:
    from tqdm import tqdm  # type: ignore
except Exception:  # pragma: no cover
    tqdm = None  # type: ignore

# Config loader
from .core.config import load_config

# Modul-modul
from .modules import (
    subdomains,
    sensitive_paths,
    open_redirect,
    documents,
    sensitive_params,
    jwt_candidates,
    params,
    robots,
    emails,
)

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run all passive URL parsers in sequence with optional YAML config overrides."
    )
    p.add_argument("--scope", required=True, help="Root domain, e.g. example.com")
    p.add_argument("--input", required=True, help="Input file from gau/waymore (.txt or .gz)")
    p.add_argument("--out", required=True, help="Output directory for this scope")
    p.add_argument("--config", default="", help="Path to YAML config to override module defaults")

    # Global scoping
    p.add_argument("--include-external", action="store_true", help="Include hosts outside the root scope")
    p.add_argument("--allow-subdomains", default="", help="Comma-separated glob allow list")
    p.add_argument("--deny-subdomains",  default="", help="Comma-separated glob deny list")

    # Module-specific CLI toggles (tetap ada; config YAML bisa override ini juga jika kamu mau)
    p.add_argument("--redirect-only-offsite", action="store_true",
                   help="open_redirect: only keep values that look offsite (http(s)://, //, %2f%2f)")

    p.add_argument("--email-domains", default="",
                   help="emails: extra allowed email domains (comma-separated) besides common providers + in-scope")
    p.add_argument("--emails-scan-path", action="store_true",
                   help="emails: also scan path segments (default off to avoid @2x.png)")
    p.add_argument("--emails-emit-raw", action="store_true",
                   help="emails: also write raw emails to emails_found.txt")
    p.add_argument("--emails-mask", action="store_true",
                   help="emails: mask raw emails in emails_found.txt")

    p.add_argument("--robots-dir", default="",
                   help="robots: directory containing <host>.robots.txt bodies to parse Disallow")
    p.add_argument("--robots-no-disallow", action="store_true",
                   help="robots: do not write robots_disallow.txt even if robots-dir provided")

    # params module noise control
    p.add_argument("--params-min-len", type=int, default=1,
                   help="params: minimum parameter name length (default 1)")
    p.add_argument("--params-exclude", default="",
                   help="params: extra excludes (comma-separated), case-insensitive")
    p.add_argument("--params-keep-case", action="store_true",
                   help="params: keep original case (default lowercases)")

    return p.parse_args()

def _merge_extra_with_config(name: str, extra: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge kwargs 'extra' (dari CLI defaults) dengan override dari config YAML untuk modul 'name'.
    - cfg[name] harus dict → di-update ke extra
    - nilai di config akan MENGGANTIKAN nilai extra
    """
    merged = dict(extra)
    section = cfg.get(name)
    if isinstance(section, dict):
        merged.update(section)
    return merged

def _print_summary_table(results: List[Tuple[str, int, int]]) -> None:
    if not results:
        return
    name_w = max(len(r[0]) for r in results + [("Module",0,0)])
    in_w   = max(len(str(r[1])) for r in results + [("",len("Input"),0)])
    out_w  = max(len(str(r[2])) for r in results + [("",0,len("Written"))])

    def line(ch="-") -> str:
        return f"+{ch*(name_w+2)}+{ch*(in_w+2)}+{ch*(out_w+2)}+"

    header = f"| {'Module'.ljust(name_w)} | {'Input'.rjust(in_w)} | {'Written'.rjust(out_w)} |"

    print()
    print(line("="))
    print(header)
    print(line("="))
    for (n, i, o) in results:
        print(f"| {n.ljust(name_w)} | {str(i).rjust(in_w)} | {str(o).rjust(out_w)} |")
    print(line("="))

def main() -> None:
    args = parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Parse global lists
    allow = [s.strip() for s in args.allow_subdomains.split(",") if s.strip()]
    deny  = [s.strip() for s in args.deny_subdomains.split(",") if s.strip()]
    extra_email_domains = [s.strip().lower() for s in args.email_domains.split(",") if s.strip()]
    params_excludes = [s.strip() for s in args.params_exclude.split(",") if s.strip()]
    robots_dir = args.robots_dir.strip() or None

    # Load YAML config (boleh kosong)
    cfg = load_config(args.config) if args.config else {}

    # Steps: (name, func, default_extra_kwargs)
    steps: List[Tuple[str, Any, Dict[str, Any]]] = [
        ("subdomains", subdomains.run, dict()),
        ("sensitive_paths", sensitive_paths.run, dict()),
        ("open_redirect", open_redirect.run, dict(
            only_offsite_values=args.redirect_only_offsite
        )),
        ("documents", documents.run, dict()),
        ("sensitive_params", sensitive_params.run, dict()),
        ("jwt_candidates", jwt_candidates.run, dict()),
        ("params", params.run, dict(
            min_len=args.params_min_len,
            exclude=list({*params_excludes}) or None,
            lowercase=not args.params_keep_case
        )),
        ("robots", robots.run, dict(
            robots_dir=robots_dir,
            write_disallow=not args.robots_no_disallow
        )),
        ("emails", emails.run, dict(
            email_domains=extra_email_domains or None,
            scan_path=args.emails_scan_path,
            emit_raw_emails=args.emails_emit_raw,
            mask_emails=args.emails_mask
        )),
    ]

    results: List[Tuple[str, int, int]] = []

    iterable = steps
    if tqdm:
        iterable = tqdm(steps, desc="Modules", unit="mod")

    for item in iterable:
        name, func, extra_defaults = item if tqdm else item
        extra = _merge_extra_with_config(name, extra_defaults, cfg)

        try:
            total_in, total_out = func(
                input_path=args.input,
                output_dir=args.out,
                scope=args.scope,
                include_external=args.include_external,
                allow_subdomains=allow or None,
                deny_subdomains=deny or None,
                **extra
            )
            results.append((name, total_in, total_out))
            status = "✅" if total_out > 0 else "⚠️"
            msg = f"[{name}] {status} read={total_in} -> written={total_out}"
        except Exception as e:
            results.append((name, 0, 0))
            msg = f"[{name}] ❌ ERROR: {e}"

        if tqdm:
            iterable.write(msg)
        else:
            print(msg)

    _print_summary_table(results)
    print(f"Done. Outputs in: {out_dir.resolve()}")

if __name__ == "__main__":
    main()
