"""
Targets Utility Functions
-------------------------

Shared helper functions for ReconLens target modules.

Includes:
    - File I/O and JSON helpers
    - Meta and scan status updates
    - URL and hostname merging
    - Size / timestamp formatting
    - Enrich cache operations
"""

from __future__ import annotations
import json, os, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# JSON / File Utilities
# ---------------------------------------------------------------------------

def safe_json_load(p: Path) -> Dict[str, Any]:
    """Safely load a JSON file; return {} on error or if file doesn't exist."""
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def safe_read_json(p: Path) -> Dict[str, Any]:
    """Alias for safe_json_load, kept for backward compatibility."""
    return safe_json_load(p)


def read_text_lines(p: Path) -> int:
    """Count number of lines in a text file."""
    try:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Merge Utilities
# ---------------------------------------------------------------------------

def merge_urls(target: Path, incoming: Path):
    """Merge two URL lists (unique, case-sensitive)."""
    seen = set()
    if target.exists():
        for ln in target.read_text(encoding="utf-8", errors="ignore").splitlines():
            if ln:
                seen.add(ln.strip())

    for ln in incoming.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = ln.strip()
        if s and s not in seen:
            seen.add(s)

    tmp = target.with_suffix(".tmp")
    tmp.write_text("\n".join(sorted(seen)) + "\n", encoding="utf-8")
    tmp.replace(target)


_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def merge_hostnames(target: Path, incoming: Path):
    """Merge hostnames (tolerant: also extracts host from full URLs)."""
    def normalize(line: str) -> Optional[str]:
        s = line.strip()
        if not s:
            return None
        if "://" in s:
            try:
                h = urlparse(s).netloc.lower()
            except Exception:
                return None
        else:
            h = s.lower()
        h = h.strip(".")
        if not _HOST_RE.match(h):
            return None
        return h

    seen = set()
    if target.exists():
        for ln in target.read_text(encoding="utf-8", errors="ignore").splitlines():
            h = normalize(ln)
            if h:
                seen.add(h)

    for ln in incoming.read_text(encoding="utf-8", errors="ignore").splitlines():
        h = normalize(ln)
        if h and h not in seen:
            seen.add(h)

    tmp = target.with_suffix(".tmp")
    tmp.write_text("\n".join(sorted(seen)) + "\n", encoding="utf-8")
    tmp.replace(target)


# ---------------------------------------------------------------------------
# Formatting Helpers
# ---------------------------------------------------------------------------

def fmt_size_human(v: Any) -> Optional[str]:
    """Convert byte count to human-readable format."""
    if v in (None, "", "-", "None"):
        return None
    try:
        n = int(float(v))
    except Exception:
        return None

    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    return f"{f:.1f} {units[i]}" if i > 0 else f"{int(f)} {units[i]}"


def fmt_last_probe(v: Any) -> Optional[str]:
    """Normalize ISO or epoch timestamps into 'YYYY-MM-DD HH:MM:SS UTC'."""
    if v in (None, "", "-", "None"):
        return None
    if isinstance(v, str) and ("T" in v or "-" in v and ":" in v):
        s = v.replace("T", " ")
        m = re.match(r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})", s)
        return m.group(1) if m else s
    try:
        sec = int(float(v))
        dt = datetime.fromtimestamp(sec, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(v)


# ---------------------------------------------------------------------------
# Enrich Handling
# ---------------------------------------------------------------------------

def url_enrich_path(outputs_root: Path, scope: str) -> Path:
    cache_dir = outputs_root / scope / "__cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "url_enrich.json"


def load_url_enrich(outputs_root: Path, scope: str) -> Dict[str, Any]:
    """Load per-URL enrich data from cache."""
    p = url_enrich_path(outputs_root, scope)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def save_url_enrich(outputs_root: Path, scope: str, data: dict):
    """Save enrich cache to disk."""
    p = url_enrich_path(outputs_root, scope)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def update_url_enrich_from_dirsearch(outputs_root: Path, scope: str, url: str,
                                     code: int, size: Optional[int]):
    """Upsert enrich record for a URL discovered by Dirsearch."""
    data = load_url_enrich(outputs_root, scope)
    rec = data.get(url) or {}
    rec.update({
        "mode": "GET",
        "code": code,
        "size": size,
        "last_probe": datetime.now(timezone.utc).isoformat(),
        "alive": (200 <= code < 500),
    })
    data[url] = rec
    save_url_enrich(outputs_root, scope, data)

# ---------------------------------------------------------------------------
# Host / Scope Utilities
# ---------------------------------------------------------------------------

def host_no_port(netloc: str) -> str:
    """Return hostname without port number."""
    if not netloc:
        return ""
    h = netloc.lower()
    if ":" in h:
        h = h.split(":", 1)[0]
    return h


def all_hosts_for_scope(outputs_root: Path, scope: str) -> List[str]:
    """
    Collect all hostnames from subdomain cache (__cache/subdomains_enrich.json).
    Returns sorted list of normalized hosts.
    """
    cache = outputs_root / scope / "__cache" / "subdomains_enrich.json"
    data = safe_json_load(cache)
    res: set[str] = set()

    for k, rec in (data or {}).items():
        final = rec.get("final_url") or k
        u = final if "://" in str(final) else f"https://{final}"
        try:
            p = urlparse(u)
            host = (p.netloc or p.path or "").split(":")[0].lower()
            if host:
                res.add(host)
        except Exception:
            pass

    return sorted(res)


# ---------------------------------------------------------------------------
# File Stats and Dashboard Aggregation
# ---------------------------------------------------------------------------

def stat_file(p: Path) -> tuple[int, int]:
    """Return (line_count, file_size_bytes) for given path."""
    if not p.exists():
        return 0, 0
    try:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            lines = sum(1 for _ in f)
        return lines, p.stat().st_size
    except Exception:
        return 0, p.stat().st_size if p.exists() else 0


def list_category_files(scope: str, outputs_root: Path) -> List[str]:
    """
    Return available module category files for a given scope.
    Includes known default categories plus dynamically detected *.txt files.
    """
    out_dir = outputs_root / scope
    known = {
        "subdomains", "auth_login", "admin_panel", "api", "upload", "download_dump",
        "debug_dev", "docs_swagger", "config_backup_source", "sensitive_functionality",
        "monitoring", "payments", "static_assets", "file_disclosure", "other",
    }

    files = [p.stem for p in sorted(out_dir.glob("*.txt")) if p.stem != "urls"]
    if "subdomains" in files:
        files.remove("subdomains")
        files = ["subdomains"] + files

    seen, ordered = set(), []
    for k in (["subdomains"] + sorted(known - {"subdomains"}) + files):
        if k not in seen and (out_dir / f"{k}.txt").exists():
            seen.add(k)
            ordered.append(k)
    return ordered

OUTPUTS_DIR = Path("outputs")
def gather_stats(scope: str) -> dict:
    out_dir = OUTPUTS_DIR / scope
    if not out_dir.exists():
        return {
            "stats": [],
            "urls_count": 0,
            "dash": {
                "totals": {},
                "status_counts": {},
                "ctypes": {},
                "last_scans": {},
            },
        }

    # 1) hitung urls.txt
    urls_path = out_dir / "urls.txt"
    urls_count = count_lines(urls_path)

    # 2) kumpulkan semua file .txt di outputs/<scope> (ini modul2)
    stats_list = []
    subdomains_lines = 0
    for p in sorted(out_dir.glob("*.txt")):
        mod = p.stem.lower()
        lines = count_lines(p)
        row = {
            "module": mod,
            "file": p.name,
            "lines": lines,
            "size_bytes": p.stat().st_size if p.exists() else 0,
        }
        if mod == "subdomains":
            subdomains_lines = lines
            row["hosts"] = lines
        stats_list.append(row)

    # 3) baca meta.json kalau ada
    meta = safe_json_load(out_dir / "meta.json")
    last_scans = meta.get("last_scans", {})
    status_counts = meta.get("status_counts", {})
    ctypes = meta.get("ctypes", {})

    # 4) ambil timestamp paling baru dari semua last_scans
    last_probe_iso = None
    if last_scans:
        try:
            last_probe_iso = max(last_scans.values())
        except Exception:
            last_probe_iso = None

    # 4) bangun dash yang dipakai template

    agg = load_http_aggregates(OUTPUTS_DIR, scope)
    live_urls = agg["live_urls"]
    dash = {
        # diisi sendiri dari file, walaupun meta.json kosong
        "totals": {
            "urls": urls_count,
            "hosts": subdomains_lines,
            "live_urls": live_urls,
        },
        "status_counts": status_counts or {},
        "ctypes": ctypes or {},
        "last_scans": last_scans,
        "last_probe_iso": last_probe_iso,
    }


    dash["status_counts"] = agg["status_counts"]
    dash["ctypes"] = agg["content_types"]

    return {
        "stats": stats_list,
        "urls_count": urls_count,
        "dash": dash,
    }

def count_lines(p: Path) -> int:
    """Return number of non-empty lines in a text file."""
    if not p.exists():
        return 0
    try:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for ln in f if ln.strip())
    except Exception:
        return 0


def load_url_enrich_raw(outputs_root: Path, scope: str) -> dict:
    """
    Load __cache/url_enrich.json as-is.
    Return {} if missing/bad.
    """
    cache = outputs_root / scope / "__cache" / "url_enrich.json"
    if not cache.exists():
        return {}
    try:
        return json.loads(cache.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def count_live_urls_from_enrich(outputs_root: Path, scope: str) -> int:
    """
    Count how many URLs are marked alive=true in url_enrich.json.
    Format bisa dict atau list (kayak versi lama), jadi kita toleran.
    """
    raw = load_url_enrich_raw(outputs_root, scope)
    cnt = 0

    if isinstance(raw, dict):
        for _, rec in raw.items():
            if not isinstance(rec, dict):
                continue
            if rec.get("alive") is True:
                cnt += 1
    elif isinstance(raw, list):
        for rec in raw:
            if not isinstance(rec, dict):
                continue
            if rec.get("alive") is True:
                cnt += 1
    return cnt

def load_http_aggregates(outputs_root: Path, scope: str) -> dict:
    """
    Read HTTP/probe metadata from outputs/<scope>/__cache/url_enrich.json
    and produce small aggregates for the dashboard.

    Returns a dict with:
        {
            "live_urls": int,
            "status_counts": { "200": 12, ... },   # top 5
            "content_types": { "text/html": 20, ... }  # top 3
        }
    """
    enrich_path = outputs_root / scope / "__cache" / "url_enrich.json"
    print(enrich_path)
    if not enrich_path.exists():
        return {
            "live_urls": 0,
            "status_counts": {},
            "content_types": {},
        }

    try:
        enrich_data = json.loads(enrich_path.read_text(encoding="utf-8"))
    except Exception:
        # corrupted or partial file; return empty aggregates
        return {
            "live_urls": 0,
            "status_counts": {},
            "content_types": {},
        }

    live_urls = 0
    status_tmp: dict[str, int] = {}
    ctype_tmp: dict[str, int] = {}

    for _url, rec in enrich_data.items():
        if not isinstance(rec, dict):
            continue

        # count alive
        if rec.get("alive") is True:
            live_urls += 1

        # count status codes
        code = rec.get("code")
        if code is not None:
            key = str(code)
            status_tmp[key] = status_tmp.get(key, 0) + 1

        # count content-types (normalize "text/html; charset=UTF-8" -> "text/html")
        ctype = rec.get("content_type")
        if ctype:
            base = ctype.split(";", 1)[0].strip()
            ctype_tmp[base] = ctype_tmp.get(base, 0) + 1

    # keep top-N only
    status_counts = dict(
        sorted(status_tmp.items(), key=lambda x: x[1], reverse=True)[:5]
    )
    content_types = dict(
        sorted(ctype_tmp.items(), key=lambda x: x[1], reverse=True)[:3]
    )

    return {
        "live_urls": live_urls,
        "status_counts": status_counts,
        "content_types": content_types,
    }