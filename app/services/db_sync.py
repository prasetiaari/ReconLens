from __future__ import annotations
import sqlite3
import json
from pathlib import Path
import time
from urllib.parse import urlparse

def get_db_path(outputs_dir: str | Path, scope: str) -> Path:
    return Path(outputs_dir) / scope / "target.db"

def init_db(outputs_dir: str | Path, scope: str):
    db_path = get_db_path(outputs_dir, scope)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # Table for module texts (many-to-many relationship theoretically, though usually 1-to-many)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS module_urls (
            url TEXT,
            module TEXT,
            PRIMARY KEY (url, module)
        )
    ''')
    
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
    
    # Indexes for faster queries
    cur.execute('CREATE INDEX IF NOT EXISTS idx_module ON module_urls(module)')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_enrich_code ON enrich_data(code)')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_enrich_host ON enrich_data(host)')
    
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

def sync_module(outputs_dir: str | Path, scope: str, module_name: str, force: bool = False):
    db_path = get_db_path(outputs_dir, scope)
    txt_path = Path(outputs_dir) / scope / f"{module_name}.txt"
    
    if not txt_path.exists():
        return

    mtime = get_mtime(txt_path)
    
    conn = sqlite3.connect(db_path)
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
        data = [(u, module_name) for u in urls]
        cur.executemany("INSERT INTO module_urls (url, module) VALUES (?, ?)", data)
    
    _set_sync_mtime(cur, f"module_{module_name}", mtime)
    conn.commit()
    conn.close()

def sync_enrich(outputs_dir: str | Path, scope: str, force: bool = False):
    db_path = get_db_path(outputs_dir, scope)
    enrich_path = Path(outputs_dir) / scope / "__cache" / "url_enrich.json"
    
    if not enrich_path.exists():
        return

    mtime = get_mtime(enrich_path)
    
    conn = sqlite3.connect(db_path)
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

def sync_target(outputs_dir: str | Path, scope: str):
    """
    Main entry point to synchronize a target's text files with its SQLite DB.
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
