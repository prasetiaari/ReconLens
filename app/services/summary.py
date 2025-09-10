# app/services/summary.py

from __future__ import annotations
from pathlib import Path
from collections import Counter
from urllib.parse import urlparse
import json
from typing import Dict, Any, Iterable, Tuple, Optional
from datetime import datetime, timezone


def _load_json(path: Path) -> Optional[dict]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _iter_enrich_records(enrich_map: dict) -> Iterable[Tuple[str, dict]]:
    # enrich_map: {canonical_url: {alive, code, content_type, ...}}
    for k, v in (enrich_map or {}).items():
        if isinstance(v, dict):
            yield k, v

def _host_of(canon_url: str) -> str:
    try:
        return urlparse(canon_url).hostname or ""
    except Exception:
        return ""

def _last_probe_iso(outputs: Path, scope: str) -> Optional[str]:
    cache = outputs / scope / "__cache"

    # 1) Coba pakai status files
    status_files = [
        cache / "url_probe_status.json",
        cache / "subdomains_probe_status.json",
        cache / "sensitive_paths_probe_status.json",
    ]
    best_iso = None
    for p in status_files:
        d = _load_json(p)
        if not d:
            continue
        # gunakan salah satu key yang tersedia
        cand = d.get("last_completed_iso") or d.get("last_probe_iso") or d.get("mtime_iso")
        if cand and (best_iso is None or cand > best_iso):
            best_iso = cand

    if best_iso:
        return best_iso

    # 2) Fallback ke mtime dari NDJSON bila status file tidak ada
    probe_ndjson = [
        cache / "url_probe.ndjson",
        cache / "subdomains_probe.ndjson",
        cache / "sensitive_paths_probe.ndjson",
    ]
    best_mtime = 0.0
    for p in probe_ndjson:
        try:
            if p.exists():
                mt = p.stat().st_mtime
                if mt > best_mtime:
                    best_mtime = mt
        except Exception:
            pass

    if best_mtime > 0:
        return datetime.fromtimestamp(best_mtime, tz=timezone.utc).isoformat()

    return None

def _load_enrich_union(outputs: Path, scope: str) -> Dict[str, dict]:
    cache_dir = outputs / scope / "__cache"

    # Prefer url_enrich.json (gabungan semua modul)
    merge = _load_json(cache_dir / "url_enrich.json")
    if isinstance(merge, dict):
        return merge

    # Fallback: gabungkan file per-modul jika ada
    result: Dict[str, dict] = {}
    for name in ("subdomains_enrich.json", "sensitive_paths_enrich.json"):
        d = _load_json(cache_dir / name)
        if isinstance(d, dict):
            result.update(d)
    return result

def build_dashboard_summary(outputs_dir: str | Path, scope: str) -> Dict[str, Any]:
    """
    Menghasilkan ringkasan untuk target_detail dashboard:
    - total_urls, live_urls, unique_hosts, last_probe_iso
    - top_codes (max 5)   -> [{code, count}]
    - top_ctypes (max 3)  -> [{ctype, count}]
    - modules: ringkas ukuran/siap view (biar kartu module yang di bawah tetap tampil)
    """
    outputs = Path(outputs_dir)
    cache_dir = outputs / scope / "__cache"

    enrich = _load_enrich_union(outputs, scope)

    total_urls = 0
    live_urls = 0
    hosts = set()
    code_ctr: Counter[int] = Counter()
    ctype_ctr: Counter[str] = Counter()

    for canon, rec in _iter_enrich_records(enrich):
        total_urls += 1
        if rec.get("alive"):
            live_urls += 1

        # host
        h = _host_of(canon)
        if h:
            hosts.add(h)

        # code
        code = rec.get("code")
        if isinstance(code, int):
            code_ctr[code] += 1

        # content-type
        ct = rec.get("content_type")
        if isinstance(ct, str) and ct:
            main = ct.split(";", 1)[0].strip().lower()
            if main:
                ctype_ctr[main] += 1

    # top lists
    top_codes = [{"code": c, "count": n} for c, n in code_ctr.most_common(5)]
    top_ctypes = [{"ctype": c, "count": n} for c, n in ctype_ctr.most_common(3)]

    # last probe iso
    last_iso = _last_probe_iso(outputs, scope)

    # data per-module untuk kartu bawah (file name + size + lines)
    def _file_info(fname: str) -> dict:
        p = outputs / scope / fname
        size = p.stat().st_size if p.exists() else 0
        lines = 0
        if p.exists():
            try:
                with p.open("r", encoding="utf-8", errors="ignore") as f:
                    for lines, _ in enumerate(f, start=1):
                        pass
            except Exception:
                lines = 0
        return {"file": fname, "size": size, "lines": lines, "ready": p.exists()}

    modules = {
        "subdomains": _file_info("subdomains.txt"),
        "sensitive_paths": _file_info("sensitive_paths.txt"),
        "open_redirect": _file_info("open_redirect_candidates.txt"),
    }

    return {
        "total_urls": total_urls,
        "live_urls": live_urls,
        "unique_hosts": len(hosts),
        "last_probe_iso": last_iso,  # template akan render pakai |timeago kalau ada
        "top_codes": top_codes,
        "top_ctypes": top_ctypes,
        "modules": modules,
    }
