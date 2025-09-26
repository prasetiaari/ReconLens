# app/tools/registry.py
from typing import Dict, Any, List, Tuple
from pathlib import Path
import asyncio
import httpx
import re

TOOLS = {}

def register_tool(id: str, meta: Dict[str,Any]):
    TOOLS[id] = meta

def get_tool(id: str):
    return TOOLS.get(id)

# httprobe adapter implementation (in-Python)
async def run_httprobe(scope: str, targets: List[str], args: Dict[str,Any], outputs_dir: Path, log_writer) -> Dict[str,Any]:
    concurrency = int(args.get("concurrency", 50))
    timeout = float(args.get("timeout", 10))
    sem = asyncio.Semaphore(concurrency)
    client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
    alive = []
    async def check(u):
        async with sem:
            try:
                resp = await client.head(u, timeout=timeout)
                return (u, resp.status_code)
            except Exception:
                # try get
                try:
                    r = await client.get(u, timeout=timeout)
                    return (u, getattr(r, "status_code", None))
                except Exception:
                    return (u, None)

    # normalize targets lines (hosts/subdomains)
    jobs = [check(t if re.match(r"^https?://", t) else f"http://{t}" ) for t in targets]
    total = len(jobs)
    await log_writer(f"Starting httprobe for {total} targets\n")
    results = await asyncio.gather(*jobs, return_exceptions=False)
    for u, code in results:
        if code and int(code) < 400:
            alive.append(u)
    # write outputs
    outdir = outputs_dir
    outdir.mkdir(parents=True, exist_ok=True)
    alive_p = outdir / "alive.txt"
    alive_p.write_text("\n".join(alive), encoding="utf-8")
    await log_writer(f"httprobe done: {len(alive)} alive / {total}\n")
    await client.aclose()
    return {"alive_count": len(alive), "total": total, "path": str(alive_p)}
