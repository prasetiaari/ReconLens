# app/core/config_store.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple

# Lokasi file config (aman di luar web-root; masih di bawah project)
# Silakan ubah kalau mau: mis. Path("outputs/__config/settings.json")
CONFIG_PATH = Path("outputs/__config/settings.json")


def _ensure_parent(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)


def _deep_merge(dst: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge rekursif: nilai di src akan menimpa dst.
    """
    for k, v in (src or {}).items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def default_settings() -> Dict[str, Any]:
    # Default mengikuti struktur yg dipakai template settings.html
    return {
        "http": {
            "user_agent": {"mode": "default", "value": ""},
            "timeout": 10,
            "concurrency": 20,
            "headers": [],  # [{"key":"Header-Name","value":"value"}]
            "proxy": {"enabled": False, "url": ""},
        },
        "tools": {
            "urlscan_api": "",
            "virustotal_api": "",
            "waymore_sources": "",
            "urls_limit": 0,
            "dirsearch_wordlist": "",
            "dirsearch_ext": "",
            "prefer_https": True,
            "if_head_then_get": True,
            "delay_ms": 0,
        },
        "ui": {
            "theme": "light",
            "retention_days": 0,
        },
        "ai": {
            "model": "llama3.2:3b",
            "autorun": False,
        },
    }


def load_settings() -> Dict[str, Any]:
    """
    Baca settings dari file. Jika belum ada, kembalikan default.
    Jika file korup, fallback ke default (tanpa melempar exception).
    """
    try:
        if CONFIG_PATH.exists():
            raw = CONFIG_PATH.read_text(encoding="utf-8")
            data = json.loads(raw) if raw.strip() else {}
        else:
            data = {}
    except Exception:
        data = {}

    base = default_settings()
    if isinstance(data, dict):
        _deep_merge(base, data)
    return base


def save_settings(new_data: Dict[str, Any]) -> Tuple[bool, list[str]]:
    """
    Simpan settings dengan merge ke yang lama.
    """
    try:
        cur = load_settings()
        if not isinstance(new_data, dict):
            return False, ["Invalid settings payload"]

        merged = default_settings()
        _deep_merge(merged, cur)
        _deep_merge(merged, new_data)

        _ensure_parent(CONFIG_PATH)
        CONFIG_PATH.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
        return True, []
    except Exception as e:
        return False, [str(e)]
