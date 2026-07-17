import sys, re
from pathlib import Path

f = Path("tools/probe_urls.py")
content = f.read_text()

# 1. Update _runner arguments
content = content.replace(
"""async def _runner(
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
) -> Tuple[int, int]:""",
"""async def _runner(
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
    advanced: bool = False,
    only_alive: bool = False,
) -> Tuple[int, int]:"""
)

# 2. Add filtering in _runner before httpx client
content = content.replace(
"""    cache_dir = outputs / scope / "__cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    ndjson_path = cache_dir / "url_probe.ndjson"
    module_enrich_path = cache_dir / f"{source}_enrich.json\"""",
"""    cache_dir = outputs / scope / "__cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    ndjson_path = cache_dir / "url_probe.ndjson"
    module_enrich_path = cache_dir / f"{source}_enrich.json"

    if only_alive:
        from app.services.enrich_urls import load_url_enrich, canon_url
        enrich_url = load_url_enrich(outputs, scope) or {}
        alive_urls = []
        for u in urls:
            cu = canon_url(u)
            rec = enrich_url.get(cu)
            if rec and rec.get("alive") is True:
                alive_urls.append(u)
        print(f"[info] --only-alive filtered from {len(urls)} to {len(alive_urls)} URLs")
        urls = alive_urls"""
)

# 3. Update worker to fetch GET and OPTIONS if advanced
content = content.replace(
"""            async with sem:
                rec = await fetch_url(client, u, timeout=timeout, mode=mode, retries=retries)
                if rec.get("is_connect_error") and port_key:
                    dead_ports.add(port_key)
                return u, rec""",
"""            async with sem:
                actual_mode = "GET" if advanced else mode
                rec = await fetch_url(client, u, timeout=timeout, mode=actual_mode, retries=retries)
                if rec.get("is_connect_error") and port_key:
                    dead_ports.add(port_key)
                
                # Fetch OPTIONS for advanced mode
                if advanced and rec.get("alive"):
                    try:
                        r_opt = await client.options(u, timeout=timeout)
                        if "allow" in r_opt.headers:
                            allow_header = r_opt.headers["allow"]
                            methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
                            rec["supported_methods"] = methods
                            print(f"[debug] {u} -> ALLOW: {methods}")
                    except Exception:
                        pass
                
                return u, rec"""
)

# 4. Update argparse
content = content.replace(
"""    ap.add_argument("--source", required=True, help="Module/source name (e.g., sensitive_paths, documents)")
    ap.add_argument("--mode", default="GET", choices=["GET", "HEAD"], help="HTTP method")
    ap.add_argument("--concurrency", type=int, default=12, help="Concurrent workers")""",
"""    ap.add_argument("--source", required=True, help="Module/source name (e.g., sensitive_paths, documents)")
    ap.add_argument("--mode", default="HEAD", choices=["GET", "HEAD"], help="HTTP method")
    ap.add_argument("--advanced", action="store_true", help="Perform advanced probe (GET + OPTIONS)")
    ap.add_argument("--only-alive", action="store_true", help="Only probe URLs marked as alive in url_enrich.json")
    ap.add_argument("--concurrency", type=int, default=12, help="Concurrent workers")"""
)

# 5. Update _runner call in main
content = content.replace(
"""            timeout=args.timeout,
            ua=args.ua,
            retries=args.retries,
            headers=headers,
        )
    )""",
"""            timeout=args.timeout,
            ua=args.ua,
            retries=args.retries,
            headers=headers,
            advanced=args.advanced,
            only_alive=args.only_alive,
        )
    )"""
)

f.write_text(content)
print("probe_urls.py patched")
