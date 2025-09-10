# urls_parser/core/fingerprint.py
from __future__ import annotations

import hashlib
from typing import Dict, Iterable, List, Tuple

def _stable_params_string(params: Dict[str, List[str]]) -> str:
    """
    Bentuk string stabil dari params:
    - kunci diurutkan alfabet
    - nilai per kunci juga diurutkan (untuk dedup yang agresif)
      (catatan: kalau ingin mempertahankan order asli, ganti strategi ini)
    - format: key=val1&key=val2&b=1
    """
    if not params:
        return ""
    parts: List[str] = []
    for k in sorted(params.keys()):
        vals = params[k]
        # urutkan nilai agar 'a=1& a=2' == 'a=2& a=1'
        for v in sorted(vals):
            parts.append(f"{k}={v}")
    return "&".join(parts)

def fingerprint_parts(host: str, path: str, params: Dict[str, List[str]]) -> str:
    """
    Fingerprint stabil berbasis host | path | params_terurut
    (scheme & port diabaikan agar konsolidasi lebih luas; sesuaikan kebutuhan).
    """
    params_str = _stable_params_string(params)
    base = f"{host}|{path}|{params_str}"
    return hashlib.sha1(base.encode("utf-8")).hexdigest()

def fingerprint_full_url(parsed: Dict) -> str:
    """
    Terima output dari url_utils.parse_url() lalu hasilkan fingerprint.
    """
    host = parsed.get("host") or ""
    path = parsed.get("path") or "/"
    params = parsed.get("params") or {}
    return fingerprint_parts(host, path, params)
