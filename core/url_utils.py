# urls_parser/core/url_utils.py
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, unquote_plus

# --- Konstanta & regex dasar ---

STATIC_EXT = {
    "png","jpg","jpeg","gif","svg","ico","webp",
    "woff","woff2","ttf","otf","eot",
    "css","js","map",
    "mp4","webm","mov","avi","mp3","wav","flac",
}
DEFAULT_PORT = {"http": 80, "https": 443}
HTTP_SCHEMES = {"http", "https"}

# Base64/URLsafe quick check (tidak dipakai di sini, tapi berguna modul lain)
RE_B64URL_CHARS = re.compile(r"^[A-Za-z0-9_\-]+=*$")

# --- Util kecil ---

def _safe_lower(s: Optional[str]) -> Optional[str]:
    return s.lower() if isinstance(s, str) else s

def is_http_url(url: str) -> bool:
    try:
        parsed = urlparse(url.strip())
        return parsed.scheme in HTTP_SCHEMES and bool(parsed.netloc)
    except Exception:
        return False

def decode_percent_once(s: str) -> str:
    """Decode percent-encoding sekali (hindari double-decode)."""
    try:
        return unquote_plus(s)
    except Exception:
        return s

def normalize_host(host: str) -> str:
    """Lowercase host. IPv6 tetap apa adanya (tanpa [] karena urlparse sudah handle)."""
    return _safe_lower(host) or ""

def extract_host_port(netloc: str, scheme: str) -> Tuple[str, Optional[int]]:
    """
    Pecah host & port dari netloc. Hilangkan default port (80/443) -> port=None.
    """
    host = netloc
    port: Optional[int] = None

    if host.startswith("["):  # IPv6 [::1]:8080
        # urlparse netloc untuk IPv6 biasanya "[::1]:8080"
        if "]" in host:
            end = host.rfind("]")
            h = host[: end + 1]
            rest = host[end + 1 :]
            host_only = h
            if rest.startswith(":"):
                try:
                    port = int(rest[1:])
                except Exception:
                    port = None
            host = host_only
    else:
        if ":" in host:
            h, p = host.rsplit(":", 1)
            host = h
            try:
                port = int(p)
            except Exception:
                port = None

    host = normalize_host(host)
    # Drop default port
    if port is not None and scheme in DEFAULT_PORT and port == DEFAULT_PORT[scheme]:
        port = None
    return host, port

def normalize_path(path: str) -> str:
    """
    Pastikan path diawali '/', buang duplikat slash, namun tidak melakukan resolve '..'
    agar tidak mengubah semantics dari URL historis.
    """
    if not path:
        return "/"
    # jaga leading slash
    if not path.startswith("/"):
        path = "/" + path
    # kompres multiple '/'
    path = re.sub(r"/{2,}", "/", path)
    return path

def get_extension(path: str) -> Optional[str]:
    """Ambil ekstensi file (tanpa titik), lowercase, atau None kalau tak ada."""
    if "." not in path:
        return None
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return None
    ext = name.rsplit(".", 1)[-1].lower()
    return ext or None

def is_static_asset(path: str) -> bool:
    ext = get_extension(path)
    return ext in STATIC_EXT if ext else False

def parse_params(query: str) -> Dict[str, List[str]]:
    """
    Parse query string → dict nama→list nilai (preserve duplicate params).
    Nilai & nama di-decode satu kali (percent & '+').
    """
    params: Dict[str, List[str]] = {}
    if not query:
        return params
    for k, v in parse_qsl(query, keep_blank_values=True):
        k_dec = k.strip()
        v_dec = v
        # sudah di-decode oleh parse_qsl (percent & plus), tapi kita sanitize ringan:
        if k_dec not in params:
            params[k_dec] = [v_dec]
        else:
            params[k_dec].append(v_dec)
    return params

# --- Fungsi utama: parse_url ---

def parse_url(url_raw: str) -> Dict:
    """
    Parse URL mentah menjadi bagian-bagian terstruktur.
    - Hanya support http/https; lainnya dikembalikan 'invalid=True'.
    - Melakukan normalisasi ringan (host lowercase, path dinormalisasi).
    - Tidak mengubah urutan nilai param; namun dedup/normalisasi lanjutan
      bisa dilakukan di modul fingerprint.
    """
    url_raw = (url_raw or "").strip()
    data = {
        "url_raw": url_raw,
        "valid": False,
        "scheme": None,
        "host": None,
        "port": None,
        "path": None,
        "query": None,
        "params": {},     # dict[str, list[str]]
        "fragment": None,
    }
    if not url_raw:
        return data

    try:
        pu = urlparse(url_raw)
    except Exception:
        return data

    if pu.scheme not in HTTP_SCHEMES or not pu.netloc:
        return data

    host, port = extract_host_port(pu.netloc, pu.scheme)
    path = normalize_path(decode_percent_once(pu.path or "/"))
    query_raw = pu.query or ""
    fragment = pu.fragment or None
    params = parse_params(query_raw)

    data.update({
        "valid": True,
        "scheme": pu.scheme,
        "host": host,
        "port": port,
        "path": path,
        "query": query_raw,
        "params": params,
        "fragment": fragment,
    })
    return data
