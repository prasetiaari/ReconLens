from __future__ import annotations
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import httpx

CACHE_DIRNAME = "__cache"
PROBE_FILE = "subdomains_probe.ndjson"
STATE_FILE = "subdomains_probe.state.json"
LOCK_FILE  = "subdomains_probe.lock"

# --- util path & io ---

def _scope_cache(outputs_dir: Path, scope: str) -> Path:
    outputs_dir = Path(outputs_dir)
    p = (outputs_dir / scope / CACHE_DIRNAME)
    p.mkdir(parents=True, exist_ok=True)
    return p

def ndjson_path(outputs_dir: Path, scope: str) -> Path:
    return _scope_cache(outputs_dir, scope) / PROBE_FILE

def state_path(outputs_dir: Path, scope: str) -> Path:
    return _scope_cache(outputs_dir, scope) / STATE_FILE

def lock_path(outputs_dir: Path, scope: str) -> Path:
    return _scope_cache(outputs_dir, scope) / LOCK_FILE

def load_probe_map(outputs_dir: Path, scope: str) -> Dict[str, Dict[str, Any]]:
    p = ndjson_path(outputs_dir, scope)
    result: Dict[str, Dict[str, Any]] = {}
    if not p.exists():
        return result
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                host = str(rec.get("host") or "").strip()
                if host:
                    result[host] = rec
            except Exception:
                continue
    return result

# helper kecil
def _first_existing(*paths: Path) -> Path | None:
    for p in paths:
        if p and p.exists():
            return p
    return None

def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def _load_ndjson(path: Path) -> list[dict]:
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out

def get_probe_map_cached(outputs_dir: Path, scope: str) -> Dict[str, Dict[str, Any]]:
    """
    Kembalikan {host: {alive, code, size, title, last_probe}}.
    Mendukung beberapa layout:
    - outputs/scope/subdomains_enrich.json
    - outputs/scope/.cache/subdomains_probe_status.json
    - outputs/scope/__cache/subdomains_probe.state.json
    - outputs/scope/.cache/subdomains_probe.ndjson
    - outputs/scope/__cache/subdomain_probe.ndjson
    """
    base = Path(outputs_dir) / scope

    # 1) format 'enrich' langsung
    enrich_path = _first_existing(
        base / "__cache" / "subdomains_enrich.json",
        base / ".cache"   / "subdomains_enrich.json",
        base / "subdomains_enrich.json",  # fallback lama kalau ada
    )
    if enrich_path:
        data = _load_json(enrich_path)
        # pastikan dict[str, dict]
        return data if isinstance(data, dict) else {}

    # 2) status map (varian nama)
    status_path = _first_existing(
        base / ".cache" / "subdomains_probe_status.json",
        base / "__cache" / "subdomains_probe_status.json",
        base / "__cache" / "subdomains_probe.state.json",
    )
    if status_path:
        data = _load_json(status_path)
        # normalisasi nama field bila perlu
        # ekspektasi: {host: {alive, code, size, title, last_probe}}
        if isinstance(data, dict):
            # beberapa generator menyimpan timestamp di field "ts" atau "time"
            for rec in data.values():
                if isinstance(rec, dict):
                    if "last_probe" not in rec:
                        ts = rec.get("ts") or rec.get("time") or rec.get("timestamp")
                        if ts:
                            rec["last_probe"] = ts
            return data

    # 3) NDJSON (varian nama & folder)
    ndjson_path = _first_existing(
        base / ".cache" / "subdomains_probe.ndjson",
        base / "__cache" / "subdomains_probe.ndjson",
        base / "__cache" / "subdomain_probe.ndjson",  # <- yang kamu punya
    )
    if ndjson_path:
        rows = _load_ndjson(ndjson_path)
        agg: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            host = r.get("host") or r.get("domain") or r.get("target")
            if not host:
                continue
            # ambil data terakhir untuk host (ndjson biasanya streaming)
            rec = agg.setdefault(host, {})
            # map field umum
            if "alive" in r:    rec["alive"] = bool(r["alive"])
            if "code"  in r:    rec["code"]  = r["code"]
            if "size"  in r:    rec["size"]  = r["size"]
            if "title" in r:    rec["title"] = r["title"]
            # timestamp varian
            ts = r.get("last_probe") or r.get("ts") or r.get("time") or r.get("timestamp")
            if ts:
                rec["last_probe"] = ts
        return agg

    # fallback: kosong
    return {}
    
def _write_state(p: Path, data: Dict[str, Any]) -> None:
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

def _read_state(p: Path) -> Dict[str, Any]:
    if not p.exists():
        return {"status": "idle"}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"status": "unknown"}

def _append_ndjson(p: Path, rec: Dict[str, Any]) -> None:
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

# --- probing ---

DEFAULT_TIMEOUT = 8.0
DEFAULT_MAX_BODY = 16_384  # 16KB cukup untuk title
DEFAULT_UA = "Pentest-Viewer/0.1 (+local)"

async def _fetch_title(client: httpx.AsyncClient, url: str) -> tuple[int|None, int|None, str|None]:
    try:
        r = await client.get(url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
        code = r.status_code
        size = len(r.content or b"")
        title = None
        if r.headers.get("content-type","").lower().startswith("text/html"):
            # cari <title> sederhana (tanpa bs4)
            text = (r.text or "")[:DEFAULT_MAX_BODY]
            import re
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            if m:
                title = m.group(1).strip()
        return code, size, title
    except Exception:
        return None, None, None

async def _probe_host(client: httpx.AsyncClient, host: str) -> Dict[str, Any]:
    # coba https dulu lalu http
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        code, size, title = await _fetch_title(client, url)
        if code is not None:
            return {
                "host": host,
                "scheme": scheme,
                "code": code,
                "size": size,
                "title": title,
                "alive": (200 <= code < 600),
                "checked_at": datetime.now(timezone.utc).isoformat()
            }
    # gagal kedua-duanya
    return {
        "host": host,
        "scheme": None,
        "code": None,
        "size": None,
        "title": None,
        "alive": False,
        "checked_at": datetime.now(timezone.utc).isoformat()
    }

# task registry sederhana (di memory) agar bisa tahu sedang jalan
_running_tasks: Dict[str, asyncio.Task] = {}

async def _run_probe(
    outputs_dir: Path,
    scope: str,
    hosts: List[str],
    concurrency: int = 20,
    mode: str = "all",
) -> None:
    """
    Worker utama: mem-probe daftar host secara async, menulis hasil ke NDJSON
    dan progress ke state.json. Men-set last_* saat selesai sukses.
    """
    sp = state_path(outputs_dir, scope)
    np = ndjson_path(outputs_dir, scope)
    lp = lock_path(outputs_dir, scope)

    # siapkan state awal; pertahankan last_* lama bila ada
    state = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": None,
        "done": 0,
        "total": len(hosts),
        "alive": 0,
        "error": None,
    }
    old = _read_state(sp)
    for k in ("last_success_at", "last_mode", "last_total", "last_alive", "last_duration_ms"):
        if k in old:
            state[k] = old[k]
    _write_state(sp, state)

    # reset cache untuk run baru
    np.unlink(missing_ok=True)
    lp.write_text("lock", encoding="utf-8")

    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(headers={"User-Agent": DEFAULT_UA}, verify=False) as client:
        async def worker(h: str):
            nonlocal state
            async with sem:
                rec = await _probe_host(client, h)
                _append_ndjson(np, rec)
                state["done"] += 1
                if rec.get("alive"):
                    state["alive"] += 1
                state["updated_at"] = datetime.now(timezone.utc).isoformat()
                _write_state(sp, state)

        try:
            await asyncio.gather(*(worker(h) for h in hosts))
            # sukses
            state["status"] = "done"
            state["updated_at"] = datetime.now(timezone.utc).isoformat()
            # hitung durasi & set last_*
            try:
                t0 = datetime.fromisoformat(state["started_at"])
                t1 = datetime.fromisoformat(state["updated_at"])
                dur_ms = int((t1 - t0).total_seconds() * 1000)
            except Exception:
                dur_ms = None
            state["last_success_at"] = state["updated_at"]
            state["last_mode"] = mode
            state["last_total"] = state.get("total", 0)
            state["last_alive"] = state.get("alive", 0)
            state["last_duration_ms"] = dur_ms
        except Exception as e:
            # gagal (biarkan last_* dari run sukses sebelumnya tetap ada)
            state["status"] = "error"
            state["error"] = str(e)
            state["updated_at"] = datetime.now(timezone.utc).isoformat()
        finally:
            _write_state(sp, state)
            lp.unlink(missing_ok=True)
            _running_tasks.pop(scope, None)

def is_running(outputs_dir: Path, scope: str) -> bool:
    # kalau ada task in-memory atau ada lock file
    if scope in _running_tasks and not _running_tasks[scope].done():
        return True
    return lock_path(outputs_dir, scope).exists()

def read_status(outputs_dir: Path, scope: str) -> Dict[str, Any]:
    return _read_state(state_path(outputs_dir, scope))

def start_probe(
    outputs_dir: Path,
    scope: str,
    hosts: Iterable[str],
    concurrency: int = 20,
    mode: str = "all",
) -> bool:
    """
    Mulai background probe. Return False jika sudah ada job berjalan
    (ditandai lock file atau task in-memory).
    """
    # sudah ada task berjalan?
    if scope in _running_tasks and not _running_tasks[scope].done():
        return False
    if lock_path(outputs_dir, scope).exists():
        return False

    task = asyncio.create_task(
        _run_probe(outputs_dir, scope, list(hosts), concurrency=concurrency, mode=mode)
    )
    _running_tasks[scope] = task
    return True
