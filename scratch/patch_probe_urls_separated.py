import sys, re
from pathlib import Path

f = Path("tools/probe_urls.py")
content = f.read_text()

# 1. Update _runner args
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
    advanced: bool = False,
    only_alive: bool = False,
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
    only_alive: bool = False,
) -> Tuple[int, int]:"""
)

# 2. Update fetch_url to handle OPTIONS natively and parse Allow header
content = content.replace(
"""            if mode == "HEAD":
                r = await client.head(url, follow_redirects=True, timeout=timeout)
            else:
                r = await client.get(url, follow_redirects=True, timeout=timeout)
            rec["alive"] = True
            rec["code"] = r.status_code
            rec["size"] = len(r.content)
            rec["content_type"] = r.headers.get("content-type")
            rec["final_url"] = str(r.url)

            # Naive <title> parse (cukup untuk preview)
            text = r.text[:3000]
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            if m:
                rec["title"] = re.sub(r"\\s+", " ", m.group(1)).strip()""",
"""            if mode == "HEAD":
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
                    rec["title"] = re.sub(r"\\s+", " ", m.group(1)).strip()"""
)

# 3. Remove Advanced code from worker
content = content.replace(
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
                
                return u, rec""",
"""            async with sem:
                rec = await fetch_url(client, u, timeout=timeout, mode=mode, retries=retries)
                if rec.get("is_connect_error") and port_key:
                    dead_ports.add(port_key)
                return u, rec"""
)

# 4. Update argparse
content = content.replace(
"""    ap.add_argument("--source", required=True, help="Module/source name (e.g., sensitive_paths, documents)")
    ap.add_argument("--mode", default="HEAD", choices=["GET", "HEAD"], help="HTTP method")
    ap.add_argument("--advanced", action="store_true", help="Perform advanced probe (GET + OPTIONS)")
    ap.add_argument("--only-alive", action="store_true", help="Only probe URLs marked as alive in url_enrich.json")""",
"""    ap.add_argument("--source", required=True, help="Module/source name (e.g., sensitive_paths, documents)")
    ap.add_argument("--mode", default="HEAD", choices=["GET", "HEAD", "OPTIONS"], help="HTTP method")
    ap.add_argument("--only-alive", action="store_true", help="Only probe URLs marked as alive in url_enrich.json")"""
)

# 5. Update _runner call in main
content = content.replace(
"""            timeout=args.timeout,
            ua=args.ua,
            retries=args.retries,
            headers=headers,
            advanced=args.advanced,
            only_alive=args.only_alive,
        )
    )""",
"""            timeout=args.timeout,
            ua=args.ua,
            retries=args.retries,
            headers=headers,
            only_alive=args.only_alive,
        )
    )"""
)

f.write_text(content)
print("tools/probe_urls.py patched successfully")
