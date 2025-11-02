from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any


def _scope_dir(outputs_root: Path, scope: str) -> Path:
    return (outputs_root / scope).resolve()

def _safe_json_load(p: Path) -> dict:
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}

def _meta_path(outputs_root: Path, scope: str) -> Path:
    return _scope_dir(outputs_root, scope) / "meta.json"


def load_meta(outputs_root: Path, scope: str) -> Dict[str, Any]:
    """Read outputs/<scope>/meta.json with safe defaults."""
    p = _meta_path(outputs_root, scope)
    if not p.exists():
        return {
            "scope": scope,
            "created_at": int(datetime.now(timezone.utc).timestamp()),
            "created_by": "ui",
            "notes": "",
            "last_scans": {},
            "dirsearch_hosts": {},
        }
    try:
        data = json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        data = {}

    # ensure keys exist
    data.setdefault("scope", scope)
    data.setdefault("created_at", int(datetime.now(timezone.utc).timestamp()))
    data.setdefault("created_by", "ui")
    data.setdefault("notes", "")
    data.setdefault("last_scans", {})
    data.setdefault("dirsearch_hosts", {})
    return data


def save_meta(outputs_root: Path, scope: str, **updates) -> None:
    """
    Update or create outputs/<scope>/meta.json (shallow merge).
    Use only primitive/dict merges—no app-specific imports here.
    """
    out_dir = _scope_dir(outputs_root, scope)
    out_dir.mkdir(parents=True, exist_ok=True)

    p = _meta_path(outputs_root, scope)
    meta = load_meta(outputs_root, scope)

    for k, v in updates.items():
        if isinstance(v, dict) and isinstance(meta.get(k), dict):
            meta[k].update(v)
        else:
            meta[k] = v

    p.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def update_last_scan(scope: str, tool_or_module: str, outputs_root: Path) -> None:
    """Record last scan timestamp for a tool/module (e.g., 'build', 'admin_panel')."""
    utc = datetime.now(timezone.utc).isoformat()
    save_meta(outputs_root, scope, last_scans={tool_or_module: utc})


def update_dirsearch_last(outputs_root: Path, scope: str, host: str) -> None:
    """
    Update per-host last run timestamp for dirsearch:
      outputs/<scope>/__cache/dirsearch_last.json
    Format:
      { "<host>": "<iso8601>" }
    """
    cache_dir = outputs_root / scope / "__cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    p = cache_dir / "dirsearch_last.json"

    data = _safe_json_load(p)
    data[host] = datetime.now(timezone.utc).isoformat()

    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def load_dirsearch_last(outputs_root: Path, scope: str) -> dict[str, str]:
    """Return dict {host: iso8601} for UI hints."""
    p = outputs_root / scope / "__cache" / "dirsearch_last.json"
    return _safe_json_load(p)