#!/usr/bin/env python3
# tools/probe_paths.py
from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from tqdm import tqdm

# Import utilitas yang sama seperti di probe_urls.py
from ..app.services.enrich_urls import (
    canon_url,
    save_enrich_map_atomic,
    merge_into_url_enrich,
)

# ---------------------- Konstanta & helper path ------------------------------

CACHE_DIRNAME = "__cache"
SUBDOMAINS_ENRICH_NAME = "subdomains_enrich.json"
PROBE_PATHS_ENRICH_NAME = "probe_paths_enrich.json"
NDJSON_LOG_NAME = "probe_paths.ndjson"

DEFAULT_UA = "ReconLens/ProbePaths"
DEFAULT_CONCURRENCY = 200
DEFAULT_PER_HOST = 8
DEFAULT_TIMEOUT = 10.0
DEFAULT_RETRIES = 2


def _outputs_scope_dir(outputs_dir: Path | str, scope: str) -> Path:
    return Path(outputs_dir) / scope


def _outputs_scope_cache_dir(outputs_dir: Path | str, scope: str) -> Path:
    return _outputs_scope_dir(outputs_dir, scope) / CACHE_DIRNAME


def _subdomains_enrich_path(outputs_dir: Path | str, scope: str) -> Path:
    return _outputs_scope_cache_dir(outputs_dir, scope) / SUBDOMAINS_ENRICH_NAME


def _probe_paths_enrich_path(outputs_dir: Path | str, scope: str) -> Path:
    return _outputs_scope_cache_dir(outputs_dir, scope) / PROBE_PATHS_ENRICH_NAME


def _ndjson_log_path(outputs_dir: Path | str, scope: str) -> Path:
    return _outputs_scope_cache_dir(outputs_dir, scope) / NDJSON_LOG_NAME


def _probe_paths_txt_path(outputs_dir: Path | str, scope: str) -> Path:
    # simpan di folder scope (bukan __cache/)
    return _outputs_scope_dir(outputs_dir, scope) / "probe_paths.txt"


def _read_json_memo(p: Path) -> Dict[str, Any]:
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _now_ts() -> int:
    return int(time.time())


def _now_iso() -> str:
    # ISO UTC (Z) agar konsisten
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


# ------------------------------ Data model -----------------------------------

@dataclass
class PathSpec:
    path: str
    method: str
    body: Optional[str] = None


@dataclass
class Target:
    scheme: str
    host: str
    port: Optional[int] = None
    source_key: str = ""
    meta: Dict[str, Any] = None

    def base_url(self) -> str:
        netloc = self.host if self.port is None else f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}"


# ------------------------ Load subdomains & paths ----------------------------

def load_live_subdomains(subdomains_enrich_file: Path, include_statuses: set[int]) -> List[Target]:
    """
    Ambil host hidup dari subdomains_enrich.json.
    Default filter: code==200 (bisa diubah via --include-statuses).
    """
    data = _read_json_memo(subdomains_enrich_file)
    targets: List[Target] = []
    for key, info in data.items():
        code = info.get("code")
        if code not in include_statuses:
            continue
        final = info.get("final_url") or key
        parsed = urlparse(final if final.startswith("http") else f"https://{final}")
        scheme = (info.get("scheme") or parsed.scheme or "https").lower()
        host = (parsed.hostname or "").strip()
        if not host:
            continue
        port = parsed.port
        targets.append(Target(scheme=scheme, host=host, port=port, source_key=key, meta=info or {}))

    # dedup by (scheme, host, port)
    uniq: Dict[Tuple[str, str, Optional[int]], Target] = {}
    for t in targets:
        uniq[(t.scheme, t.host, t.port)] = t
    return list(uniq.values())


def load_paths_csv(p: Path) -> List[PathSpec]:
    specs: List[PathSpec] = []
    with p.open("r", encoding="utf-8", errors="ignore") as fh:
        rdr = csv.reader(fh)
        for row in rdr:
            if not row:
                continue
            path = (row[0] or "").strip()
            method = (row[1] or "GET").strip().upper()
            body = (row[2] if len(row) > 2 else None)
            if not path or path == ".":
                path = "/"
            if not path.startswith("/"):
                path = "/" + path
            specs.append(PathSpec(path=path, method=method, body=body if body not in ("", None) else None))
    return specs


def load_paths_ndjson(p: Path) -> List[PathSpec]:
    specs: List[PathSpec] = []
    with p.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            path = (obj.get("path") or "/").strip()
            method = (obj.get("method") or "GET").strip().upper()
            body = obj.get("body", None)
            if not path.startswith("/"):
                path = "/" + path
            specs.append(PathSpec(path=path, method=method, body=body if body not in ("", None) else None))
    return specs


def load_paths_file(path_file: Path) -> List[PathSpec]:
    suf = path_file.suffix.lower()
    if suf in (".ndjson", ".jsonl", ".json"):
        return load_paths_ndjson(path_file)
    return load_paths_csv(path_file)


# ----------------------------- HTTP probing ----------------------------------

def _infer_content_headers(body: Optional[str]) -> Tuple[Optional[bytes], Dict[str, str]]:
    """
    Infer Content-Type sederhana dari body string.
    '@/path/file' akan dibaca sebagai raw bytes (content).
    """
    if body is None:
        return None, {}
    if isinstance(body, str) and body.startswith("@"):
        fp = Path(body[1:])
        try:
            return fp.read_bytes(), {}
        except Exception as e:
            return f"__ERROR_READING_BODY_FILE__:{e}".encode(), {}
    # string biasa
    b = body.encode()
    headers: Dict[str, str] = {}
    if body.lstrip().startswith(("{", "[")):
        headers["Content-Type"] = "application/json"
    elif "=" in body and "&" in body and not re.search(r"\s", body):
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return b, headers


async def fetch_path(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    method: str,
    body: Optional[str],
    ua: str,
    follow_redirects: bool,
) -> Dict[str, Any]:
    """
    Mirip gaya fetch_* di probe_urls.py:
    return dict berisi alive, code, size, title, content_type, final_url, ts, last_probe, mode, error, sources
    """
    url = base_url.rstrip("/") + path
    payload, add_headers = _infer_content_headers(body)
    headers = {"User-Agent": ua}
    headers.update(add_headers)

    started = time.time()
    record: Dict[str, Any] = {
        "alive": False,
        "code": None,
        "size": None,
        "title": None,
        "content_type": None,
        "final_url": url,
        "ts": _now_ts(),
        "last_probe": _now_iso(),
        "mode": method,
        "error": None,
        "sources": ["probe_paths"],
    }

    try:
        resp = await client.request(
            method=method,
            url=url,
            headers=headers,
            content=payload if (payload is not None and not isinstance(payload, str)) else payload,
            follow_redirects=follow_redirects,
        )

        # title extraction sederhana
        title = None
        ctype = resp.headers.get("content-type")
        if ctype and "html" in ctype.lower():
            try:
                text_for_title = resp.text[:4096]
                m = re.search(r"<title>(.*?)</title>", text_for_title, re.I | re.S)
                if m:
                    title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
            except Exception:
                pass

        record.update(
            alive=True,  # respon didapat (meski 4xx/5xx)
            code=resp.status_code,
            size=len(resp.content) if resp.content is not None else None,
            title=title,
            content_type=ctype,
            final_url=str(resp.url),
            sha1=hashlib.sha1(resp.content or b"").hexdigest(),
            snippet=(resp.text or "")[:512] if hasattr(resp, "text") else None,
            redirects=[str(r.url) for r in getattr(resp, "history", [])] if getattr(resp, "history", None) else [],
            latency_ms=int((time.time() - started) * 1000),
        )

    except httpx.HTTPError as e:
        record["error"] = str(e)
        record["alive"] = False

    return record


# ------------------------------ Runner core ----------------------------------

async def _runner(
    outputs_dir: Path | str,
    scope: str,
    targets: List[Target],
    pathspecs: List[PathSpec],
    *,
    concurrency: int,
    per_host: int,
    timeout: float,
    retries: int,
    ua: str,
    proxy: Optional[str],
    insecure: bool,
    follow_redirects: bool,
) -> Dict[str, Any]:
    """
    Jalankan semua kombinasi (base_url x pathspec), tulis NDJSON log,
    hasil akhir gabung ke probe_paths_enrich.json lalu merge ke url_enrich.json,
    dan tulis daftar URL probed ke outputs/<scope>/probe_paths.txt
    """
    cache_dir = _outputs_scope_cache_dir(outputs_dir, scope)
    cache_dir.mkdir(parents=True, exist_ok=True)
    ndjson_path = _ndjson_log_path(outputs_dir, scope)

    # siapkan client httpx
    timeout_cfg = httpx.Timeout(timeout)
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    client_args: Dict[str, Any] = {"timeout": timeout_cfg, "limits": limits}
    if proxy:
        client_args["proxies"] = proxy
    if insecure:
        client_args["verify"] = False

    # build semua tasks
    work: List[Tuple[str, str, str, Optional[str]]] = []  # (base, path, method, body)
    for t in targets:
        base = t.base_url()
        for ps in pathspecs:
            work.append((base, ps.path, ps.method, ps.body))

    # Kumpulkan daftar host/path (tanpa scheme) untuk probe_paths.txt
    host_paths_for_txt: List[str] = []
    for base, path, _method, _body in work:
        url = base.rstrip("/") + ("/" if path == "/" else path)
        host_paths_for_txt.append(url)

    # siapkan map hasil untuk enrich
    module_map: Dict[str, Any] = _read_json_memo(_probe_paths_enrich_path(outputs_dir, scope)) or {}
    first_seen_default = _now_ts()

    # tulis NDJSON streaming
    nd_fh = ndjson_path.open("a", encoding="utf-8")

    sem_host: Dict[str, asyncio.Semaphore] = {}

    async with httpx.AsyncClient(**client_args) as client:
        pbar = tqdm(total=len(work), desc="probe_paths", unit="req")

        async def do_one(base: str, path: str, method: str, body: Optional[str]):
            host = urlparse(base).hostname or base
            sem = sem_host.setdefault(host, asyncio.Semaphore(per_host))
            async with sem:
                rec = await fetch_path(
                    client, base, path, method, body, ua=ua, follow_redirects=follow_redirects
                )
            # key untuk enrich map: canon_url(base+path)
            key = canon_url(base.rstrip("/") + path)

            # isi/merge record & first_seen
            prev = module_map.get(key)
            if prev and isinstance(prev, dict):
                first_seen = prev.get("first_seen", first_seen_default)
            else:
                first_seen = first_seen_default
            rec["first_seen"] = first_seen

            module_map[key] = rec

            # tulis ndjson line
            nd_fh.write(json.dumps({"url": key, **rec}, ensure_ascii=False) + "\n")
            pbar.update(1)

        # batasi concurrency global
        sem_all = asyncio.Semaphore(concurrency)

        async def wrap_do_one(args_tuple):
            base, path, method, body = args_tuple
            async with sem_all:
                await do_one(base, path, method, body)

        await asyncio.gather(*(wrap_do_one(w) for w in work))
        pbar.close()

    nd_fh.close()

    # simpan module map -> probe_paths_enrich.json
    save_enrich_map_atomic(_probe_paths_enrich_path(outputs_dir, scope), module_map)

    # merge ke url_enrich.json (konsisten dengan probe_urls.py)
    merge_into_url_enrich(outputs_dir, scope, module_map)

    # tulis probe_paths.txt (unik & sorted) di folder scope
    probe_txt_path = _probe_paths_txt_path(outputs_dir, scope)
    probe_txt_path.parent.mkdir(parents=True, exist_ok=True)
    uniq_sorted = sorted(set(host_paths_for_txt))
    probe_txt_path.write_text("\n".join(uniq_sorted) + "\n", encoding="utf-8")

    return module_map


# --------------------------------- CLI ---------------------------------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="probe_paths.py",
        description="Probe (host × path × method) dan tulis enrich seperti probe_urls.py",
    )
    ap.add_argument("--outputs", default="output", help="Root outputs dir (default: ./output)")
    ap.add_argument("--scope", required=True, help="Scope name (mis. 'tangerangselatankota.go.id')")
    ap.add_argument("--subdomains-enrich", help="Override path ke subdomains_enrich.json (default: outputs/<scope>/__cache/subdomains_enrich.json)")
    ap.add_argument("--paths-file", required=True, help="CSV/NDJSON: kolom path,method,body (body boleh null)")
    ap.add_argument("--include-statuses", default="200", help="Status yang dianggap 'live' (csv). Default: 200")
    ap.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    ap.add_argument("--per-host", type=int, default=DEFAULT_PER_HOST)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    ap.add_argument("--ua", default=DEFAULT_UA)
    ap.add_argument("--proxy")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--no-follow-redirects", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--i-have-permission", action="store_true",
                    help="Wajib jika ada metode selain GET/HEAD/OPTIONS")
    return ap.parse_args()


def main():
    args = parse_args()

    outputs_dir = Path(args.outputs)
    scope = args.scope
    subdomains_file = Path(args.subdomains_enrich) if args.subdomains_enrich else _subdomains_enrich_path(outputs_dir, scope)
    paths_file = Path(args.paths_file)

    if not subdomains_file.exists():
        raise SystemExit(f"[ERR] subdomains enrich not found: {subdomains_file}")
    if not paths_file.exists():
        raise SystemExit(f"[ERR] paths file not found: {paths_file}")

    include_statuses = set()
    for tok in (args.include_statuses or "200").split(","):
        tok = tok.strip()
        if tok.isdigit():
            include_statuses.add(int(tok))
    if not include_statuses:
        include_statuses = {200}

    # load data
    targets = load_live_subdomains(subdomains_file, include_statuses=include_statuses)
    pathspecs = load_paths_file(paths_file)

    if not targets:
        raise SystemExit("[INFO] No targets (cek include-statuses atau subdomains file).")
    if not pathspecs:
        raise SystemExit("[INFO] No path specs in paths-file.")

    # safety metode state-changing
    unsafe = {ps.method for ps in pathspecs} - {"GET", "HEAD", "OPTIONS"}
    if unsafe and not args.i_have_permission:
        raise SystemExit("Error: state-changing methods terdeteksi (mis. POST/PUT/DELETE). Tambahkan --i-have-permission untuk lanjut.")

    if args.dry_run:
        print(f"[dry-run] hosts: {len(targets)}, pathspecs: {len(pathspecs)}")
        cnt = 0
        for t in targets[:5]:
            base = t.base_url()
            for ps in pathspecs[:3]:
                print("  ", base.rstrip("/") + ps.path, ps.method, ("(body...)" if ps.body else ""))
                cnt += 1
                if cnt >= 10:
                    break
            if cnt >= 10:
                break
        return

    # run
    asyncio.run(
        _runner(
            outputs_dir=outputs_dir,
            scope=scope,
            targets=targets,
            pathspecs=pathspecs,
            concurrency=args.concurrency,
            per_host=args.per_host,
            timeout=args.timeout,
            retries=args.retries,
            ua=args.ua,
            proxy=args.proxy,
            insecure=args.insecure,
            follow_redirects=(not args.no_follow_redirects),
        )
    )

    # done (print lokasi file)
    print(f"[OK] wrote: {_probe_paths_enrich_path(outputs_dir, scope)}")
    print(f"[OK] merged into url_enrich.json")
    print(f"[OK] wrote: {_ndjson_log_path(outputs_dir, scope)}")
    print(f"[OK] wrote: {_probe_paths_txt_path(outputs_dir, scope)}")


if __name__ == "__main__":
    main()
