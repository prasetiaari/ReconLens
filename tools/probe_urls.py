# urls_parser/tools/probe_urls.py
from __future__ import annotations

import argparse
import asyncio
import json
import re
import time
from pathlib import Path
from typing import Dict, Tuple, List, Set

import sys
import socket
from urllib.parse import urlparse
import httpx
from tqdm import tqdm

from ..app.services.enrich_urls import (
    canon_url,
    save_enrich_map_atomic,
    merge_into_url_enrich,
)

def _parse_headers_json(s: str | None) -> dict:
    if not s:
        return {}
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return {str(k): str(v) for k, v in obj.items()}
    except Exception:
        return {}

def load_url_enrich(outputs_root: Path, scope: str) -> dict:
    p = outputs_root / scope / "__cache" / "url_enrich.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8")) or {}
        except Exception:
            pass
    return {}

def _ensure_user_agent(h: dict, fallback: str | None) -> dict:
    # kalau sudah ada user-agent (case-insensitive), jangan timpa
    if any(k.lower() == "user-agent" for k in h.keys()):
        return h
    if fallback:
        h = dict(h)
        h["User-Agent"] = fallback
    return h
    
# ------------------------ HTTP fetcher ------------------------ #
async def fetch_url(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    mode: str,
    retries: int = 1,
) -> Dict:
    """
    Kembalikan record hasil probe untuk 1 URL.
    alive = True jika status < 500 (4xx dianggap up karena responsif).
    """
    last_err = None
    for _ in range(max(1, retries + 1)):
        rec = {
            "alive": False,
            "code": None,
            "size": None,
            "title": None,
            "content_type": None,
            "final_url": url,
            "last_probe": int(time.time()),
            "method": mode,
            "error": None,
        }
        try:
            if mode == "HEAD":
                r = await client.head(url, follow_redirects=True, timeout=timeout)
            elif mode == "OPTIONS":
                r = await client.options(url, timeout=timeout)
            else:
                r = await client.get(url, follow_redirects=True, timeout=timeout)
                
            rec["alive"] = True
            rec["code"] = r.status_code
            rec["size"] = len(r.content)
            rec["content_type"] = r.headers.get("content-type")
            rec["final_url"] = str(r.url)

            if mode == "OPTIONS":
                if "allow" in r.headers:
                    methods = [mx.strip().upper() for mx in r.headers["allow"].split(",") if mx.strip()]
                    rec["supported_methods"] = methods
            else:
                # Naive <title> parse (cukup untuk preview)
                text = r.text[:3000]
                m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
                if m:
                    rec["title"] = re.sub(r"\s+", " ", m.group(1)).strip()

            return rec
        except Exception as e:
            last_err = e
            rec["error"] = str(e)
            if isinstance(e, (httpx.ConnectError, httpx.ConnectTimeout)):
                rec["is_connect_error"] = True
            # coba ulang jika masih ada retries
    # kalau semua percobaan gagal, kembalikan rec terakhir
    return rec  # type: ignore[name-defined]


# ------------------------ Runner ------------------------ #
async def _runner(
    urls: List[str],
    scope: str,
    outputs: Path,
    source: str,
    mode: str,
    concurrency: int,
    timeout: int,
    ua: str,
    retries: int,
    headers: dict | None = None,
    only_alive: bool = False,
) -> Tuple[int, int]:
    """
    Probe kumpulan URL secara concurrent dan tulis:
      - __cache/<source>_enrich.json (module map)
      - __cache/url_enrich.json      (global union map; merge)
      - __cache/url_probe.ndjson     (log per-bar isian)
    """
    cache_dir = outputs / scope / "__cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    ndjson_path = cache_dir / "url_probe.ndjson"
    module_enrich_path = cache_dir / f"{source}_enrich.json"

    if only_alive:
        enrich_url = load_url_enrich(outputs, scope) or {}
        alive_urls = []
        for u in urls:
            cu = canon_url(u)
            rec = enrich_url.get(cu)
            if rec and rec.get("alive") is True:
                alive_urls.append(u)
        print(f"[info] --only-alive filtered from {len(urls)} to {len(alive_urls)} URLs")
        urls = alive_urls

    limits = httpx.Limits(
        max_connections=max(4, concurrency),
        max_keepalive_connections=max(4, concurrency),
    )

    connector_opts = dict(verify=False)

    async with httpx.AsyncClient(
        headers=headers,
        limits=limits,
        http2=False,
        follow_redirects=True,
        **connector_opts,
    ) as client:
        sem = asyncio.Semaphore(max(1, concurrency))

        dns_cache: Dict[str, bool] = {}
        in_flight: Dict[str, asyncio.Task] = {}
        dead_ports: Set[str] = set()
        start_time = time.time()

        async def check_dns(host: str) -> bool:
            if host in dns_cache:
                return dns_cache[host]
            if host in in_flight:
                return await in_flight[host]

            async def resolve():
                loop = asyncio.get_running_loop()
                try:
                    await loop.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
                    dns_cache[host] = True
                    return True
                except socket.gaierror:
                    dns_cache[host] = False
                    return False
                except Exception:
                    return True
                finally:
                    in_flight.pop(host, None)

            task = asyncio.create_task(resolve())
            in_flight[host] = task
            return await task

        async def worker(u: str) -> Tuple[str, Dict]:
            try:
                parsed = urlparse(u)
                host = parsed.hostname or ""
                scheme = parsed.scheme or "http"
                port = parsed.port
                if not port:
                    port = 443 if scheme == "https" else 80
                port_key = f"{scheme}://{host}:{port}"
            except Exception:
                host = ""
                port_key = ""

            if host:
                dns_ok = await check_dns(host)
                if not dns_ok:
                    return u, {
                        "alive": False,
                        "code": None,
                        "size": None,
                        "title": None,
                        "content_type": None,
                        "final_url": u,
                        "last_probe": int(time.time()),
                        "mode": mode,
                        "error": "Dead subdomain (DNS resolution failed)",
                    }

            if port_key and port_key in dead_ports:
                return u, {
                    "alive": False,
                    "code": None,
                    "size": None,
                    "title": None,
                    "content_type": None,
                    "final_url": u,
                    "last_probe": int(time.time()),
                    "mode": mode,
                    "error": "Dead port/scheme (Connection failed previously)",
                }

            async with sem:
                rec = await fetch_url(client, u, timeout=timeout, mode=mode, retries=retries)
                if rec.get("is_connect_error") and port_key:
                    dead_ports.add(port_key)
                return u, rec

        tasks = [asyncio.create_task(worker(u)) for u in urls]

        done = 0
        alive_count = 0
        module_map: Dict[str, Dict] = {}

        with ndjson_path.open("a", encoding="utf-8") as ndj, tqdm(
            total=len(tasks), desc=f"probe:{scope}", unit="url", disable=not sys.stderr.isatty()
        ) as pbar:
            for fut in asyncio.as_completed(tasks):
                url, rec = await fut
                cu = canon_url(url)

                # tulis ndjson (1 baris per hasil)
                ndj.write(json.dumps({cu: rec}, ensure_ascii=False) + "\n")

                # catat ke module map (overwrite by latest)
                # tambahkan metadata
                rec["sources"] = list({*(rec.get("sources") or []), source})
                rec["first_seen"] = rec.get("first_seen") or int(time.time())
                
                # accumulate methods
                old_methods = set(module_map.get(cu, {}).get("supported_methods", []))
                if "supported_methods" in rec:
                    old_methods.update(rec["supported_methods"])
                new_method = rec.get("method") or mode or "GET"
                old_methods.add(new_method.upper())
                rec["supported_methods"] = sorted(list(old_methods))
                
                module_map[cu] = rec

                # statistik
                done += 1
                if rec.get("alive"):
                    alive_count += 1
                pbar.set_postfix(alive=alive_count, err=done - alive_count)
                pbar.update(1)

                # Custom progress for frontend CLI runner
                if done % max(1, len(tasks) // 100) == 0 or done == len(tasks):
                    elapsed = time.time() - start_time
                    prog = {
                        "total": len(tasks),
                        "done": done,
                        "alive": alive_count,
                        "elapsed": round(elapsed, 1)
                    }
                    print(f"[progress] {json.dumps(prog)}")

    # Simpan peta modul & merge ke url_enrich.json
    save_enrich_map_atomic(module_enrich_path, module_map)
    merge_into_url_enrich(outputs, scope, module_map)

    duration = time.time() - start_time
    print(f"[done] total={len(tasks)} done={done} alive={alive_count} time={duration:.1f}s")
    print(f"[out] module_enrich={module_enrich_path} ndjson={ndjson_path}")
    return done, alive_count


# ------------------------ CLI ------------------------ #
def main():
    ap = argparse.ArgumentParser(description="Probe URLs asynchronously and update enrich maps.")
    ap.add_argument("--scope", required=True, help="Target scope (folder name under outputs)")
    ap.add_argument("--outputs", required=True, help="Outputs base dir (same with FastAPI settings)")
    ap.add_argument("--input", required=True, help="Text file of URLs (one per line)")
    ap.add_argument("--source", required=True, help="Module/source name (e.g., sensitive_paths, documents)")
    ap.add_argument("--mode", default="HEAD", choices=["GET", "HEAD", "OPTIONS"], help="HTTP method")
    ap.add_argument("--only-alive", action="store_true", help="Only probe URLs marked as alive in url_enrich.json")
    ap.add_argument("--concurrency", type=int, default=12, help="Concurrent workers")
    ap.add_argument("--timeout", type=int, default=20, help="Per request timeout (seconds)")
    ap.add_argument("--headers-json", help="JSON object of extra headers to send", default=None)
    ap.add_argument("--ua", help="Override User-Agent (fallback if headers not specify UA)", default="urls_parser/1.0 (+subdomains-probe)")
    ap.add_argument("--retries", type=int, default=1, help="Retries per URL on error")
    args = ap.parse_args()

    base = Path(args.outputs).resolve()
    inp = Path(args.input).resolve()
    urls = [x.strip() for x in inp.read_text(encoding="utf-8").splitlines() if x.strip()]
    
    headers = _parse_headers_json(args.headers_json)
    headers = _ensure_user_agent(headers, args.ua)
    asyncio.run(
        _runner(
            urls=urls,
            scope=args.scope,
            outputs=base,
            source=args.source,
            mode=args.mode,
            concurrency=args.concurrency,
            timeout=args.timeout,
            ua=args.ua,
            retries=args.retries,
            headers=headers,
            only_alive=args.only_alive,
        )
    )


if __name__ == "__main__":
    main()
