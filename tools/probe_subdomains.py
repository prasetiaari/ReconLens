# urls_parser/tools/probe_subdomains.py
from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import sys
from argparse import ArgumentParser
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx
from tqdm import tqdm

# ------------------------------- Consts & utils -------------------------------

CACHE_DIRNAME = "__cache"
ND_PROBE_OLD = "subdomains_probe.ndjson"       # back-compat (lama)
ND_PROBE_HOST = "probes_host.ndjson"           # baru (timeline host)
HOST_ENRICH = "subdomains_enrich.json"         # back-compat (map host -> rec)
HOST_INDEX = "host_index.json"                 # baru (ringkasan host)
HOST_IP_EDGES = "host_ip_edges.ndjson"         # baru (edge host->ip)
ROLLUP_IP = "rollup_group_by_ip.json"          # baru (siap UI)

TITLE_RE = re.compile(r"<\s*title[^>]*>(.*?)</\s*title\s*>", re.I | re.S)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def unix_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())

def read_json(path: Path, default):
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def write_json_atomic(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def append_ndjson(path: Path, record: Dict[str, Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def read_nonempty_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    out = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if s:
                out.append(s)
    return out

# ------------------------------- Networking helpers ---------------------------

async def resolve_ips(host: str) -> List[str]:
    # Non-blocking wrapper di thread, portable (tanpa dependensi aiodns).
    def _res() -> List[str]:
        ips: set[str] = set()
        with suppress(Exception):
            for fam in (socket.AF_INET, socket.AF_INET6):
                with suppress(Exception):
                    infos = socket.getaddrinfo(host, None, family=fam)
                    for info in infos:
                        ip = info[4][0]
                        ips.add(ip)
        return sorted(ips)
    return await asyncio.to_thread(_res)

async def fetch_title_if_html(client: httpx.AsyncClient, url: str, timeout: float) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[int], Optional[str], Optional[str]]:
    """
    Return: (title, code, ctype, size, final_url, error)
    """
    try:
        resp = await client.get(url, follow_redirects=True, timeout=timeout)
        code = resp.status_code
        ctype = resp.headers.get("content-type")
        size = None
        # prioritaskan Content-Length kalau ada
        with suppress(Exception):
            if resp.headers.get("content-length"):
                size = int(resp.headers["content-length"])
        if size is None:
            size = len(resp.content or b"")
        title = None
        if ctype and "html" in ctype.lower() and resp.content:
            m = TITLE_RE.search(resp.text)
            if m:
                title = re.sub(r"\s+", " ", m.group(1).strip())[:200]
        return title, code, ctype, size, str(resp.url), None
    except Exception as e:
        return None, None, None, None, None, str(e)

async def head_or_get(client: httpx.AsyncClient, url: str, timeout: float, if_head_then_get: bool) -> Tuple[Optional[int], Optional[str], Optional[int], Optional[str], Optional[str], Optional[str]]:
    """
    Kembalikan meta tanpa perlu parsing title (cepat untuk 'probe' awal).
    Return: (code, ctype, size, final_url, mode, error)
    """
    # Try HEAD
    try:
        resp = await client.head(url, follow_redirects=True, timeout=timeout)
        code = resp.status_code
        ctype = resp.headers.get("content-type")
        size = None
        with suppress(Exception):
            if resp.headers.get("content-length"):
                size = int(resp.headers["content-length"])
        return code, ctype, size, str(resp.url), "HEAD", None
    except Exception as e:
        if not if_head_then_get:
            return None, None, None, None, "HEAD", str(e)

    # Fallback GET
    try:
        resp = await client.get(url, follow_redirects=True, timeout=timeout)
        code = resp.status_code
        ctype = resp.headers.get("content-type")
        size = None
        with suppress(Exception):
            if resp.headers.get("content-length"):
                size = int(resp.headers["content-length"])
        if size is None:
            size = len(resp.content or b"")
        return code, ctype, size, str(resp.url), "GET", None
    except Exception as e:
        return None, None, None, None, "GET", str(e)

# --------------------------------- Data model ---------------------------------

@dataclass
class ProbeResult:
    host: str
    scheme: Optional[str]
    alive: bool
    code: Optional[int]
    size: Optional[int]
    title: Optional[str]
    content_type: Optional[str]
    final_url: Optional[str]
    duration_ms: int
    error: Optional[str]
    ips: List[str]

# --------------------------------- Probe core ---------------------------------

async def probe_host(client: httpx.AsyncClient, host: str, timeout: float, prefer_https: bool, if_head_then_get: bool) -> ProbeResult:
    t0 = asyncio.get_event_loop().time()

    # Resolve IP dulu (tidak fatal kalau gagal)
    ips = await resolve_ips(host)

    schemes = ["https", "http"] if prefer_https else ["http", "https"]
    best: Optional[ProbeResult] = None

    for scheme in schemes:
        url = f"{scheme}://{host}"
        # HEAD/GET cepat untuk meta
        code, ctype, size, final_url, mode, err = await head_or_get(client, url, timeout, if_head_then_get=if_head_then_get)
        t1 = asyncio.get_event_loop().time()
        dur_ms = int((t1 - t0) * 1000)

        if code is not None:
            alive = code < 500
            title = None
            # kalau GET yang jalan & content-type HTML, kita coba ambil title (opsional)
            if mode == "GET" and ctype and "html" in ctype.lower():
                with suppress(Exception):
                    title, _, _, _, _, _ = await fetch_title_if_html(client, url, timeout=timeout)
            best = ProbeResult(
                host=host, scheme=scheme, alive=alive, code=code, size=size,
                title=title, content_type=ctype, final_url=final_url, duration_ms=dur_ms,
                error=None, ips=ips
            )
            break
        else:
            # simpan error sementara (kalau semua skema gagal, pakai yang terakhir)
            best = ProbeResult(
                host=host, scheme=scheme, alive=False, code=None, size=None,
                title=None, content_type=None, final_url=None, duration_ms=dur_ms,
                error=err, ips=ips
            )

    return best or ProbeResult(
        host=host, scheme=None, alive=False, code=None, size=None,
        title=None, content_type=None, final_url=None, duration_ms=0,
        error="unreachable", ips=ips
    )

# ------------------------------- Writers (files) -------------------------------

def merge_enrich_map(old: Dict[str, Any], rec: ProbeResult, iso: str, uts: int) -> Dict[str, Any]:
    # Back-compat map host -> record
    prev = old.get(rec.host) or {}
    updated = {
        **prev,
        "scheme": rec.scheme,
        "alive": rec.alive,
        "code": rec.code,
        "size": rec.size,
        "title": rec.title,
        "content_type": rec.content_type,
        "final_url": rec.final_url,
        "ts": uts,               # numeric for legacy readers
        "last_probe": iso,       # ISO baru
    }
    old[rec.host] = updated
    return old

def merge_host_index(old: Dict[str, Any], rec: ProbeResult, iso: str) -> Dict[str, Any]:
    item = old.get(rec.host) or {}
    first_seen = item.get("first_seen") or iso
    ip_hist = set(item.get("ip_hist") or [])
    ip_now = rec.ips or []
    for ip in ip_now:
        ip_hist.add(ip)
    old[rec.host] = {
        "first_seen": first_seen,
        "last_seen": iso,
        "tags": list(set(item.get("tags") or ["subdomain"])),
        "last_probe": iso,
        "last_status": {
            "alive": rec.alive,
            "code": rec.code,
            "size": rec.size,
            "title": rec.title,
            "scheme": rec.scheme,
        },
        "ip_now": ip_now,
        "ip_hist": sorted(ip_hist),
    }
    return old

def update_edges(edges_path: Path, host: str, ips: List[str], iso: str):
    for ip in ips:
        append_ndjson(edges_path, {"ts": iso, "host": host, "ip": ip, "event": "resolve"})

def append_probe_lines(cache_dir: Path, rec: ProbeResult, iso: str):
    # legacy ndjson
    append_ndjson(cache_dir / ND_PROBE_OLD, {
        "ts": iso,
        "host": rec.host,
        "scheme": rec.scheme,
        "alive": rec.alive,
        "code": rec.code,
        "size": rec.size,
        "title": rec.title,
        "duration_ms": rec.duration_ms,
        "error": rec.error,
    })
    # new host timeline
    append_ndjson(cache_dir / ND_PROBE_HOST, {
        "ts": iso,
        "host": rec.host,
        "mode": "HEAD/GET",
        "alive": rec.alive,
        "code": rec.code,
        "size": rec.size,
        "title": rec.title,
        "content_type": rec.content_type,
        "final_url": rec.final_url,
        "duration_ms": rec.duration_ms,
        "error": rec.error,
    })

def build_rollup_group_by_ip(host_index: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Simple rollup: ip -> hosts[]
    ip_map: Dict[str, Dict[str, Any]] = {}
    for host, info in host_index.items():
        ips = info.get("ip_now") or []
        status = info.get("last_status") or {}
        for ip in ips or ["-"]:
            bucket = ip_map.setdefault(ip, {
                "ip": ip, "asn": None, "asn_name": None, "geo": None,
                "total_hosts": 0, "alive": 0, "hosts": []
            })
            bucket["total_hosts"] += 1
            alive = bool(status.get("alive"))
            if alive:
                bucket["alive"] += 1
            bucket["hosts"].append({
                "host": host,
                "alive": alive,
                "code": status.get("code"),
                "title": status.get("title"),
                "scheme": status.get("scheme"),
            })
    # sort hosts per ip for nicer output
    for v in ip_map.values():
        v["hosts"].sort(key=lambda x: (not x["alive"], x["host"]))
    return sorted(ip_map.values(), key=lambda x: (-x["alive"], -x["total_hosts"], x["ip"]))

# ----------------------------------- Main -------------------------------------

async def _runner(
    scope: str,
    outputs_dir: Path,
    subdomains_path: Path,
    concurrency: int,
    timeout: float,
    prefer_https: bool,
    if_head_then_get: bool,
):
    cache_dir = outputs_dir / scope / CACHE_DIRNAME
    cache_dir.mkdir(parents=True, exist_ok=True)

    hosts = read_nonempty_lines(subdomains_path)
    if not hosts:
        print(f"[err] no hosts in {subdomains_path}", file=sys.stderr)
        return

    # load existing
    enrich_path = cache_dir / HOST_ENRICH
    host_index_path = cache_dir / HOST_INDEX
    edges_path = cache_dir / HOST_IP_EDGES
    rollup_path = cache_dir / ROLLUP_IP

    enrich_map = read_json(enrich_path, {})
    host_index = read_json(host_index_path, {})

    # client
    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency)
    async with httpx.AsyncClient(
        http2=True,
        verify=False,  # biar ga ribet sama cert self-signed
        follow_redirects=False,
        timeout=timeout,
        limits=limits,
        headers={"User-Agent": "urls_parser/1.0 (+subdomains-probe)"},
    ) as client:

        sem = asyncio.Semaphore(concurrency)

        async def one(host: str) -> ProbeResult:
            async with sem:
                return await probe_host(client, host, timeout=timeout, prefer_https=prefer_https, if_head_then_get=if_head_then_get)

        tasks = [asyncio.create_task(one(h)) for h in hosts]

        done_alive = 0
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"probe:{scope}"):
            rec: ProbeResult = await coro
            if rec.alive:
                done_alive += 1
            iso = now_iso()
            uts = unix_ts()

            # append timelines
            append_probe_lines(cache_dir, rec, iso)

            # host_index (baru)
            host_index = merge_host_index(host_index, rec, iso)
            # edges host->ip
            if rec.ips:
                update_edges(edges_path, rec.host, rec.ips, iso)

            # back-compat enrich map
            enrich_map = merge_enrich_map(enrich_map, rec, iso, uts)

        # write atomically
        write_json_atomic(host_index_path, host_index)
        write_json_atomic(enrich_path, enrich_map)
        # quick rollup
        write_json_atomic(rollup_path, build_rollup_group_by_ip(host_index))

    print(f"\n[done] total={len(hosts)} alive={done_alive}")
    print(f"[out] enrich={enrich_path}  host_index={host_index_path}  edges={edges_path}  rollup={rollup_path}")
    print(f"[out] ndjson(old)={cache_dir/ND_PROBE_OLD}  ndjson(host)={cache_dir/ND_PROBE_HOST}")

def main():
    ap = ArgumentParser(description="Probe subdomains (HTTP + DNS), with backward-compatible outputs.")
    ap.add_argument("--scope", required=True, help="Nama scope, mis. tangerangselatankota.go.id")
    ap.add_argument("--outputs", default="urls_parser/outputs", help="Root outputs dir (default: urls_parser/outputs)")
    ap.add_argument("--input", help="Path file subdomains.txt (default: {outputs}/{scope}/subdomains.txt)")
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--prefer-https", action="store_true", help="Coba https lebih dulu")
    ap.add_argument("--if-head-then-get", action="store_true", help="Kalau HEAD gagal, coba GET")
    args = ap.parse_args()

    outputs_dir = Path(args.outputs).resolve()
    scope_dir = outputs_dir / args.scope
    subdomains_path = Path(args.input) if args.input else (scope_dir / "subdomains.txt")

    if not subdomains_path.exists():
        print(f"[err] input not found: {subdomains_path}", file=sys.stderr)
        sys.exit(2)

    asyncio.run(_runner(
        scope=args.scope,
        outputs_dir=outputs_dir,
        subdomains_path=subdomains_path,
        concurrency=max(1, args.concurrency),
        timeout=max(1.0, args.timeout),
        prefer_https=bool(args.prefer_https),
        if_head_then_get=bool(args.if_head_then_get),
    ))

if __name__ == "__main__":
    main()
