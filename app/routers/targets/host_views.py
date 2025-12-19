from pathlib import Path
import json
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from app.deps import get_settings, get_templates
from ..subdomains import  load_enrich
from .utils import (
    load_url_enrich,
)

router = APIRouter()

def _norm_host(val: str) -> str:
    """Return lowercased host without port."""
    s = (val or "").strip().lower()
    if ":" in s:
        s = s.split(":", 1)[0]
    return s


def _load_dirsearch_found(outputs_root: Path, scope: str, host: str) -> list[str]:
    """Read dirsearch per-host findings if present."""
    p = outputs_root / scope / "dirsearch" / host / "found.txt"
    if not p.exists():
        return []
    out: list[str] = []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                out.append(ln)
    return out


def _load_dirsearch_last(outputs_root: Path, scope: str) -> dict[str, str]:
    """Load __cache/dirsearch_last.json → {host: iso}."""
    p = outputs_root / scope / "__cache" / "dirsearch_last.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _load_ip_rollup(outputs_root: Path, scope: str) -> list[dict]:
    """Load rolled up IP → hosts file if exists."""
    p = outputs_root / scope / "__cache" / "rolledup_group_by_ip.json"
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


@router.get("/targets/{scope}/host/{host}", response_class=HTMLResponse)
async def host_detail(request: Request, scope: str, host: str):
    """
    Show detailed information for a specific host:
    - Basic probe info (from subdomains_enrich)
    - URLs belonging to this host (from url_enrich)
    - Dirsearch findings (from dirsearch/<host>/found.txt)
    - Neighbor hosts that share the same IP (from rolledup_group_by_ip.json)
    """
    settings = get_settings(request)
    templates = get_templates(request)
    outputs_root = Path(settings.OUTPUTS_DIR)

    norm = _norm_host(host)

    # 1) Load subdomain enrichment data (main source for probe status, code, title, etc.)
    sub_enrich = load_enrich(outputs_root, scope) or {}
    host_info = sub_enrich.get(norm) or {}

    if not host_info:
        raise HTTPException(status_code=404, detail="Host not found in subdomain cache")

    # 2) Collect all URLs belonging to this host
    url_enrich = load_url_enrich(outputs_root, scope) or {}
    host_urls: list[dict] = []
    for url, rec in url_enrich.items():
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        if _norm_host(parsed.netloc) != norm:
            continue
        host_urls.append({
            "url": url,
            "code": rec.get("code"),
            "alive": rec.get("alive"),
            "size": rec.get("size"),
            "title": rec.get("title"),
            "content_type": rec.get("content_type"),
            "last_probe": rec.get("last_probe"),
            "method": rec.get("method") or rec.get("mode") or "GET",
        })

    # Sort URLs for readability
    host_urls.sort(key=lambda x: (x.get("code") or 999, x["url"]))

    # 3) Load dirsearch findings (if available)
    dirsearch_found = _load_dirsearch_found(outputs_root, scope, norm)
    dirsearch_last_map = _load_dirsearch_last(outputs_root, scope)
    dirsearch_last = dirsearch_last_map.get(norm)

    # 4) Determine IP address and neighbor hosts (via rollup file)
    rollups = _load_ip_rollup(outputs_root, scope)
    ip_addr = host_info.get("ip") or None
    neighbors: list[dict] = []

    # Fallback: infer IP from rolledup_group_by_ip.json
    if not ip_addr:
        for grp in rollups:
            for h in grp.get("hosts", []):
                if _norm_host(h.get("host") or "") == norm:
                    ip_addr = grp.get("ip")
                    break
            if ip_addr:
                break

    if ip_addr:
        # Collect all hosts sharing this IP
        for grp in rollups:
            if grp.get("ip") != ip_addr:
                continue
            for h in grp.get("hosts", []):
                hname = h.get("host")
                if not hname or _norm_host(hname) == norm:
                    continue
                neighbors.append({
                    "host": hname,
                    "alive": h.get("alive"),
                    "code": h.get("code"),
                    "scheme": h.get("scheme"),
                })

    # 5) Prepare context for the template
    webinspectra = _load_webinspectra(outputs_root, scope, norm)
    ctx = {
        "request": request,
        "scope": scope,
        "host": norm,
        "host_info": host_info,
        "ip_addr": ip_addr,
        "urls": host_urls,
        "dirsearch_found": dirsearch_found,
        "dirsearch_last": dirsearch_last,
        "neighbors": neighbors,
        "probe_info": {
            "last_probe": host_info.get("last_probe"),
            "alive": host_info.get("alive"),
            "code": host_info.get("code"),
        },
        "webinspectra": webinspectra,
    }

    return templates.TemplateResponse("targets/host_details.html", ctx)


def _load_webinspectra(outputs_root: Path, scope: str, host: str) -> dict:
    """Load WebInspectra result for a single host, if it exists."""
    tools_dir = outputs_root / scope / "tools" / "webinspectra"
    path = tools_dir / f"{host}.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}