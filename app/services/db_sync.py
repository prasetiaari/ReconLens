from __future__ import annotations
import hashlib
import sqlite3
import json
from pathlib import Path
import time
from urllib.parse import urlparse

COUNT_CACHE_MAX_PER_MODULE = 500

def get_db_path(outputs_dir: str | Path, scope: str) -> Path:
    return Path(outputs_dir) / scope / "target.db"

def init_db(outputs_dir: str | Path, scope: str):
    db_path = get_db_path(outputs_dir, scope)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30.0)
    cur = conn.cursor()
    cur.execute('PRAGMA journal_mode=WAL')
    
    # Table for module texts
    cur.execute('''
        CREATE TABLE IF NOT EXISTS module_urls (
            url TEXT,
            module TEXT,
            host TEXT,
            PRIMARY KEY (url, module)
        )
    ''')
    
    # Migration if host column is missing
    cur.execute("PRAGMA table_info(module_urls)")
    columns = [col[1] for col in cur.fetchall()]
    if "host" not in columns:
        cur.execute("ALTER TABLE module_urls ADD COLUMN host TEXT")
    
    # Table for enrich data
    cur.execute('''
        CREATE TABLE IF NOT EXISTS enrich_data (
            url TEXT PRIMARY KEY,
            host TEXT,
            code INTEGER,
            size INTEGER,
            title TEXT,
            content_type TEXT,
            method TEXT,
            supported_methods TEXT,
            last_probe TEXT,
            alive BOOLEAN
        )
    ''')
    
    # Table to track sync state
    cur.execute('''
        CREATE TABLE IF NOT EXISTS sync_state (
            file_key TEXT PRIMARY KEY,
            mtime REAL
        )
    ''')
    
    # Table for user tags and notes
    cur.execute('''
        CREATE TABLE IF NOT EXISTS user_notes (
            url TEXT PRIMARY KEY,
            tag TEXT,
            note TEXT
        )
    ''')
    
    # Indexes for faster queries
    cur.execute('CREATE INDEX IF NOT EXISTS idx_module ON module_urls(module)')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_module_host ON module_urls(module, host)')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_enrich_code ON enrich_data(code)')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_enrich_host ON enrich_data(host)')

    # Cache: COUNT(*) per (module + filter) — invalidated by mtime
    cur.execute('''
        CREATE TABLE IF NOT EXISTS count_cache (
            module TEXT,
            fhash TEXT,
            filters TEXT,
            total INTEGER,
            txt_mtime REAL,
            enrich_mtime REAL,
            updated_at REAL,
            PRIMARY KEY (module, fhash)
        )
    ''')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_count_cache_module ON count_cache(module, updated_at)')

    # Cache: DISTINCT host dropdown per module — invalidated by mtime
    cur.execute('''
        CREATE TABLE IF NOT EXISTS host_cache (
            module TEXT PRIMARY KEY,
            hosts_json TEXT,
            txt_mtime REAL,
            enrich_mtime REAL,
            updated_at REAL
        )
    ''')

    conn.commit()
    conn.close()
    return db_path

def get_mtime(path: Path) -> float:
    return path.stat().st_mtime if path.exists() else 0.0

def _get_sync_mtime(cur: sqlite3.Cursor, file_key: str) -> float:
    cur.execute("SELECT mtime FROM sync_state WHERE file_key = ?", (file_key,))
    row = cur.fetchone()
    return row[0] if row else 0.0

def _set_sync_mtime(cur: sqlite3.Cursor, file_key: str, mtime: float):
    cur.execute("INSERT OR REPLACE INTO sync_state (file_key, mtime) VALUES (?, ?)", (file_key, mtime))


# ---------------------------------------------------------------------------
# Count / host cache (point 2: filter token + point 3: build-time precompute)
# ---------------------------------------------------------------------------

def _txt_mtime(outputs_dir: str | Path, scope: str, module_name: str) -> float:
    return get_mtime(Path(outputs_dir) / scope / f"{module_name}.txt")


def _enrich_mtime(outputs_dir: str | Path, scope: str) -> float:
    return get_mtime(Path(outputs_dir) / scope / "__cache" / "url_enrich.json")


def normalize_filter_for_hash(filt: dict) -> dict:
    """Normalize filter dict so identical semantics produce identical hash."""
    out: dict = {}
    out["q"] = " ".join(str(filt.get("q") or "").strip().split())
    out["host"] = str(filt.get("host") or "").strip().lower()
    out["scheme"] = str(filt.get("scheme") or "").strip().lower()
    codes = filt.get("codes") or []
    try:
        out["codes"] = sorted(int(c) for c in codes)
    except Exception:
        out["codes"] = sorted(str(c) for c in codes)
    out["http_class"] = str(filt.get("http_class") or "").strip().lower()
    out["ctype"] = str(filt.get("ctype") or "").strip().lower()
    out["min_size"] = filt.get("min_size")
    out["max_size"] = filt.get("max_size")
    out["method"] = str(filt.get("method") or "").strip().upper()
    return out


def make_filter_hash(module: str, filt: dict) -> tuple[str, str]:
    """Return (fhash, filter_json). Empty filter -> ('none', '{}')."""
    norm = normalize_filter_for_hash(filt or {})
    is_empty = not any([
        norm.get("q"), norm.get("host"), norm.get("scheme"),
        norm.get("codes"), norm.get("http_class"), norm.get("ctype"),
        norm.get("min_size") is not None, norm.get("max_size") is not None,
        norm.get("method"),
    ])
    if is_empty:
        return "none", "{}"
    blob = json.dumps(norm, sort_keys=True, ensure_ascii=False)
    return hashlib.md5(blob.encode("utf-8")).hexdigest(), blob


def get_cached_count(outputs_dir: str | Path, scope: str, module: str,
                     fhash: str, txt_mtime: float, enrich_mtime: float) -> int | None:
    try:
        conn = sqlite3.connect(get_db_path(outputs_dir, scope), timeout=10.0)
        cur = conn.cursor()
        cur.execute(
            "SELECT total, txt_mtime, enrich_mtime FROM count_cache WHERE module=? AND fhash=?",
            (module, fhash),
        )
        row = cur.fetchone()
        conn.close()
    except Exception:
        return None
    if not row:
        return None
    total, old_txt, old_enrich = row
    if (old_txt or 0) != (txt_mtime or 0) or (old_enrich or 0) != (enrich_mtime or 0):
        return None  # stale: file or enrich changed
    return int(total)


def set_cached_count(outputs_dir: str | Path, scope: str, module: str,
                     fhash: str, filter_json: str, total: int,
                     txt_mtime: float, enrich_mtime: float) -> None:
    try:
        conn = sqlite3.connect(get_db_path(outputs_dir, scope), timeout=30.0)
        cur = conn.cursor()
        cur.execute(
            """INSERT OR REPLACE INTO count_cache
               (module, fhash, filters, total, txt_mtime, enrich_mtime, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (module, fhash, filter_json, int(total), txt_mtime, enrich_mtime, time.time()),
        )
        # LRU eviction: keep newest N per module
        cur.execute(
            """DELETE FROM count_cache WHERE module=? AND fhash NOT IN (
                   SELECT fhash FROM count_cache WHERE module=? ORDER BY updated_at DESC LIMIT ?
               ) AND fhash != 'none'""",
            (module, module, COUNT_CACHE_MAX_PER_MODULE),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def invalidate_count_cache_for_module(outputs_dir: str | Path, scope: str, module: str) -> None:
    """Drop filtered variants on resync; 'none' is rewritten by sync_module."""
    try:
        conn = sqlite3.connect(get_db_path(outputs_dir, scope), timeout=30.0)
        cur = conn.cursor()
        cur.execute("DELETE FROM count_cache WHERE module=? AND fhash != 'none'", (module,))
        cur.execute("DELETE FROM host_cache WHERE module=?", (module,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_cached_hosts(outputs_dir: str | Path, scope: str, module: str,
                     txt_mtime: float, enrich_mtime: float) -> list | None:
    try:
        conn = sqlite3.connect(get_db_path(outputs_dir, scope), timeout=10.0)
        cur = conn.cursor()
        cur.execute("SELECT hosts_json, txt_mtime, enrich_mtime FROM host_cache WHERE module=?", (module,))
        row = cur.fetchone()
        conn.close()
    except Exception:
        return None
    if not row:
        return None
    blob, old_txt, old_enrich = row
    if (old_txt or 0) != (txt_mtime or 0) or (old_enrich or 0) != (enrich_mtime or 0):
        return None
    try:
        data = json.loads(blob or "[]")
        return data if isinstance(data, list) else None
    except Exception:
        return None


def set_cached_hosts(outputs_dir: str | Path, scope: str, module: str,
                     hosts: list, txt_mtime: float, enrich_mtime: float) -> None:
    try:
        conn = sqlite3.connect(get_db_path(outputs_dir, scope), timeout=30.0)
        cur = conn.cursor()
        cur.execute(
            """INSERT OR REPLACE INTO host_cache
               (module, hosts_json, txt_mtime, enrich_mtime, updated_at)
               VALUES (?, ?, ?, ?, ?)""",
            (module, json.dumps(hosts, ensure_ascii=False), txt_mtime, enrich_mtime, time.time()),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def sync_module(outputs_dir: str | Path, scope: str, module_name: str, force: bool = False):
    db_path = get_db_path(outputs_dir, scope)
    txt_path = Path(outputs_dir) / scope / f"{module_name}.txt"
    
    if not txt_path.exists():
        return

    mtime = get_mtime(txt_path)
    
    conn = sqlite3.connect(db_path, timeout=30.0)
    cur = conn.cursor()
    
    last_mtime = _get_sync_mtime(cur, f"module_{module_name}")
    if not force and mtime <= last_mtime:
        conn.close()
        return

    # Delete old records
    cur.execute("DELETE FROM module_urls WHERE module = ?", (module_name,))

    # Bulk insert
    with txt_path.open("r", encoding="utf-8", errors="ignore") as f:
        urls = set()
        for ln in f:
            s = ln.strip()
            if s:
                urls.add(s)

        # executemany needs tuples
        data = []
        for u in urls:
            idx = u.find("://")
            if idx != -1:
                h = u[idx+3:].split("/", 1)[0].split(":", 1)[0].lower()
            else:
                h = ""
            data.append((u, module_name, h))
        cur.executemany("INSERT INTO module_urls (url, module, host) VALUES (?, ?, ?)", data)
        built_total = len(data)

    _set_sync_mtime(cur, f"module_{module_name}", mtime)
    # Point 3: build-time precompute — count known right after sync (no extra COUNT query).
    # Invalidate filtered variants; rewrite 'none' with fresh mtimes.
    cur.execute("DELETE FROM count_cache WHERE module=? AND fhash != 'none'", (module_name,))
    cur.execute("DELETE FROM host_cache WHERE module=?", (module_name,))
    try:
        en_mtime = get_mtime(Path(outputs_dir) / scope / "__cache" / "url_enrich.json")
        cur.execute(
            """INSERT OR REPLACE INTO count_cache
               (module, fhash, filters, total, txt_mtime, enrich_mtime, updated_at)
               VALUES (?, 'none', '{}', ?, ?, ?, ?)""",
            (module_name, int(built_total), mtime, en_mtime, time.time()),
        )
    except Exception:
        pass
    conn.commit()
    conn.close()

def sync_enrich(outputs_dir: str | Path, scope: str, force: bool = False):
    db_path = get_db_path(outputs_dir, scope)
    enrich_path = Path(outputs_dir) / scope / "__cache" / "url_enrich.json"
    
    if not enrich_path.exists():
        return

    mtime = get_mtime(enrich_path)
    
    conn = sqlite3.connect(db_path, timeout=30.0)
    cur = conn.cursor()
    
    last_mtime = _get_sync_mtime(cur, "url_enrich")
    if not force and mtime <= last_mtime:
        conn.close()
        return

    # Bulk insert or replace
    try:
        data_json = json.loads(enrich_path.read_text(encoding="utf-8"))
    except Exception:
        data_json = {}

    data_tuples = []
    for url, meta in data_json.items():
        try:
            p = urlparse(url)
            host = p.netloc.lower() if p else ""
        except Exception:
            host = ""
            
        data_tuples.append((
            url,
            host,
            meta.get("code"),
            meta.get("size"),
            meta.get("title"),
            meta.get("content_type"),
            meta.get("method"),
            json.dumps(meta.get("supported_methods", [])),
            meta.get("last_probe"),
            meta.get("alive")
        ))
    
    cur.executemany('''
        INSERT OR REPLACE INTO enrich_data 
        (url, host, code, size, title, content_type, method, supported_methods, last_probe, alive) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', data_tuples)
    
    _set_sync_mtime(cur, "url_enrich", mtime)
    conn.commit()
    conn.close()

def sync_tags(outputs_dir: str | Path, scope: str, force: bool = False):
    db_path = get_db_path(outputs_dir, scope)
    tags_path = Path(outputs_dir) / scope / "__cache" / "user_tags.json"
    
    if not tags_path.exists():
        return

    mtime = get_mtime(tags_path)
    
    conn = sqlite3.connect(db_path, timeout=30.0)
    cur = conn.cursor()
    
    last_mtime = _get_sync_mtime(cur, "user_tags")
    if not force and mtime <= last_mtime:
        conn.close()
        return

    try:
        data_json = json.loads(tags_path.read_text(encoding="utf-8"))
    except Exception:
        data_json = {}

    data_tuples = []
    for url, meta in data_json.items():
        data_tuples.append((
            url,
            meta.get("tag", ""),
            meta.get("note", "")
        ))
    
    # Clear and bulk insert
    cur.execute("DELETE FROM user_notes")
    cur.executemany('''
        INSERT INTO user_notes (url, tag, note) 
        VALUES (?, ?, ?)
    ''', data_tuples)
    
    _set_sync_mtime(cur, "user_tags", mtime)
    conn.commit()
    conn.close()

def sync_target(outputs_dir: str | Path, scope: str):
    """
    Main entry point to synchronize a target's text files with its SQLite DB.
    Used by background jobs (full rebuild). View layer should prefer
    sync_single_module() so opening one module never touches other modules.
    """
    init_db(outputs_dir, scope)

    # Sync common modules that might exist
    target_dir = Path(outputs_dir) / scope
    if target_dir.exists() and target_dir.is_dir():
        for file_path in target_dir.glob("*.txt"):
            module_name = file_path.stem
            sync_module(outputs_dir, scope, module_name)

    # Sync enrich data
    sync_enrich(outputs_dir, scope)

    # Sync tags and notes
    sync_tags(outputs_dir, scope)


def sync_single_module(outputs_dir: str | Path, scope: str, module_name: str):
    """
    Point 1: sync ONLY the requested module (+ shared enrich/tags).
    Never globs *.txt, so opening `other` won't sync `urls` 4M / `catalog_noise` 3.8M.
    `tagged` has no .txt file — only enrich/tags need syncing.
    """
    init_db(outputs_dir, scope)
    mod = (module_name or "").strip().lower()
    if mod and mod != "tagged":
        sync_module(outputs_dir, scope, mod)
    sync_enrich(outputs_dir, scope)
    sync_tags(outputs_dir, scope)
