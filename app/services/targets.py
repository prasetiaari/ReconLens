from __future__ import annotations
import json
from pathlib import Path
from typing import List
from app.core.models import Summary, ModuleStat
from app.core.fs import list_subdirs, count_lines, safe_join
from urllib.parse import urlparse
from datetime import datetime, timezone

def list_scopes(outputs_dir: Path) -> List[str]:
    return list_subdirs(outputs_dir)

def load_summary(outputs_dir: Path, scope: str) -> Summary:
    folder = safe_join(outputs_dir, scope)
    p = folder / "summary.json"
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return Summary(**data)
        except Exception:
            pass
    # fallback minimal jika summary.json tidak ada
    return Summary(scope=scope, counts={}, generated_at=datetime.now().isoformat())

def build_module_stats(outputs_dir: Path, scope: str, modules_map: dict) -> List[ModuleStat]:
    folder = safe_join(outputs_dir, scope)
    stats: List[ModuleStat] = []
    for mod, fname in modules_map.items():
        fp = folder / fname
        if not fp.exists():
            continue
        stats.append(ModuleStat(
            module=mod,
            file=fname,
            size_bytes=fp.stat().st_size,
            lines=count_lines(fp),
        ))
    return stats

def _load_any_json(p: Path):
    if not p.exists():
        return None
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _iter_enrich_records(scope_dir: Path):
    """Yield normalized enrich records regardless of file/shape."""
    cdir = scope_dir / "__cache"

    # Prefer the combined file; fall back to sensitive_paths_enrich.json
    candidates = [
        cdir / "url_enrich.json",
        cdir / "sensitive_paths_enrich.json",
    ]
    data = None
    for p in candidates:
        data = _load_any_json(p)
        if data:
            break
    if not data:
        return

    # Normalize shape: either list[rec] or dict[url->rec]
    if isinstance(data, list):
        for rec in data:
            if isinstance(rec, dict):
                yield rec
    elif isinstance(data, dict):
        # Could be a mapping {url: rec} or {"records":[...]}
        if "records" in data and isinstance(data["records"], list):
            for rec in data["records"]:
                if isinstance(rec, dict):
                    yield rec
        else:
            for _url, rec in data.items():
                if isinstance(rec, dict):
                    # stash url if missing
                    rec.setdefault("url", _url)
                    yield rec

def build_target_dashboard(outputs_dir: Path, scope: str) -> dict:
    scope_dir = Path(outputs_dir) / scope

    totals_urls = 0
    totals_alive = 0
    hosts = set()
    status_counts = {}
    ctype_counts = {}
    last_ts = None

    for rec in _iter_enrich_records(scope_dir):
        totals_urls += 1

        url = rec.get("final_url") or rec.get("url")
        if url:
            try:
                h = urlparse(url).hostname
                if h:
                    hosts.add(h.lower())
            except Exception:
                pass

        code = rec.get("code")
        if code is not None:
            totals_alive += 1
            try:
                status_counts[code] = status_counts.get(code, 0) + 1
            except Exception:
                pass

        ct = rec.get("content_type")
        if ct:
            ctype_counts[ct] = ctype_counts.get(ct, 0) + 1

        # last_probe or ts (unix seconds)
        ts = rec.get("last_probe") or rec.get("ts")
        if isinstance(ts, (int, float)):
            if (last_ts is None) or (ts > last_ts):
                last_ts = int(ts)

    last_iso = None
    if last_ts:
        last_iso = datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat()

    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "totals": {
            "urls": totals_urls,
            "urls_alive": totals_alive,
            "hosts": len(hosts),
        },
        "status_counts": status_counts,
        "ctypes": ctype_counts,
        "last_probe_iso": last_iso,
    }
