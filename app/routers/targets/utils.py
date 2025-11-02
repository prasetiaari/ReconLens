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


def gather_stats(scope: str, outputs_root: Path) -> Dict[str, Any]:
    """
    Gather per-module stats and dashboard metrics for target overview page.
    Returns:
        {
            "stats": [ {module, file, lines, size_bytes}, ... ],
            "urls_count": int,
            "dash": dict
        }
    """
    out = []
    out_dir = outputs_root / scope
    if not out_dir.exists():
        return {"stats": [], "urls_count": 0, "dash": {}}

    urls_path = out_dir / "urls.txt"
    urls_count = read_text_lines(urls_path)
    modules = list_category_files(scope, outputs_root)

    for mod in modules:
        p = out_dir / f"{mod}.txt"
        lines, size = stat_file(p)
        row = {"module": mod, "file": p.name, "lines": lines, "size_bytes": size}
        if mod == "subdomains":
            row["hosts"] = lines
        out.append(row)

    # Ensure subdomains always first
    sub_p = out_dir / "subdomains.txt"
    sub_lines, sub_bytes = stat_file(sub_p)
    replaced = False
    for row in out:
        if row.get("module") == "subdomains":
            row.update({
                "file": sub_p.name,
                "lines": sub_lines,
                "hosts": sub_lines,
                "size_bytes": sub_bytes,
            })
            replaced = True
            break
    if not replaced:
        out.insert(0, {
            "module": "subdomains",
            "file": sub_p.name,
            "lines": sub_lines,
            "hosts": sub_lines,
            "size_bytes": sub_bytes,
        })

    meta = safe_json_load(out_dir / "meta.json")
    dash = {
        "totals": meta.get("totals", {}),
        "status_counts": meta.get("status_counts", {}),
        "ctypes": meta.get("ctypes", {}),
        "last_probe_iso": (meta.get("last_scans") or {}).get("probe", None),
        "last_scans": meta.get("last_scans", {}),
    }

    return {"stats": out, "urls_count": urls_count, "dash": dash}