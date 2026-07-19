import sqlite3
import json
from pathlib import Path
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse
from app.deps import get_settings, get_templates

from app.services.programs import load_programs
from app.services.program_meta import load_program_meta
from app.routers.targets.utils import gather_stats

router = APIRouter(prefix="/programs", tags=["programs_ui"])

@router.get("/{program_name}", response_class=HTMLResponse)
async def program_overview(request: Request, program_name: str):
    settings = get_settings(request)
    templates = get_templates(request)
    
    programs = load_programs(settings.OUTPUTS_DIR)
    
    if program_name not in programs:
        raise HTTPException(status_code=404, detail="Program not found")
        
    scopes = programs[program_name]
    program_meta = load_program_meta(settings.OUTPUTS_DIR).get(program_name, {})
    
    total_subs = 0
    total_urls = 0
    total_live_urls = 0
    total_hosts = 0
    scope_details = []
    
    for scope in scopes:
        stats_pack = gather_stats(scope)
        
        subs = 0
        for st in stats_pack.get("stats", []):
            if st.get("module") == "subdomains":
                subs = st.get("lines", 0)
                break
                
        urls = stats_pack.get("urls_count", 0)
        
        dash = stats_pack.get("dash", {})
        totals = dash.get("totals", {})
        live = totals.get("live_urls", 0)
        hosts = totals.get("hosts", 0)
        
        last_scans = dash.get("last_scans", {})
        last_scan = max(last_scans.values()) if last_scans else None
        
        last_scan_short = "-"
        if last_scan:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(last_scan.replace('Z', '+00:00'))
                last_scan_short = dt.strftime("%b %d, %Y")
            except:
                last_scan_short = last_scan.split('T')[0]
        
        total_subs += subs
        total_urls += urls
        total_live_urls += live
        total_hosts += hosts
        
        scope_details.append({
            "scope": scope,
            "subs": subs,
            "urls": urls,
            "live": live,
            "hosts": hosts,
            "last_scan": last_scan_short
        })
        
    scope_details.sort(key=lambda x: x["scope"])
    
    ctx = {
        "request": request,
        "program_name": program_name,
        "meta": program_meta,
        "scopes": scope_details,
        "totals": {
            "subs": total_subs,
            "urls": total_urls,
            "live": total_live_urls,
            "hosts": total_hosts
        },
        "active_tab": "overview"
    }
    
    return templates.TemplateResponse("programs/overview.html", ctx)


@router.get("/{program_name}/notes", response_class=HTMLResponse)
async def program_notes(request: Request, program_name: str, q: str = ""):
    settings = get_settings(request)
    templates = get_templates(request)
    
    programs = load_programs(settings.OUTPUTS_DIR)
    if program_name not in programs:
        raise HTTPException(status_code=404, detail="Program not found")
        
    scopes = programs[program_name]
    program_meta = load_program_meta(settings.OUTPUTS_DIR).get(program_name, {})
    
    all_notes = []
    
    for scope in scopes:
        db_path = settings.OUTPUTS_DIR / scope / "target.db"
        if not db_path.exists():
            continue
            
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            
            query = """
                SELECT n.url, n.tag, n.note, 
                       e.host, e.code, e.title, e.alive
                FROM user_notes n
                LEFT JOIN enrich_data e ON n.url = e.url
                WHERE 1=1
            """
            params = []
            
            if q:
                import re
                tokens = re.findall(r'"[^"]*"|\S+', q)
                for tok in tokens:
                    is_exclude = False
                    if tok.startswith('"') and tok.endswith('"') and len(tok) >= 2:
                        val = tok[1:-1]
                    elif tok.startswith('-') or tok.startswith('!'):
                        is_exclude = True
                        val = tok[1:]
                    else:
                        val = tok
                        
                    if not val:
                        continue
                        
                    if is_exclude:
                        query += " AND (n.url NOT LIKE ? AND COALESCE(n.note, '') NOT LIKE ? AND COALESCE(n.tag, '') NOT LIKE ?)"
                    else:
                        query += " AND (n.url LIKE ? OR COALESCE(n.note, '') LIKE ? OR COALESCE(n.tag, '') LIKE ?)"
                        
                    params.extend([f"%{val}%", f"%{val}%", f"%{val}%"])
            
            query += " ORDER BY n.url"
            
            cur.execute(query, params)
            rows = cur.fetchall()
            
            for r in rows:
                all_notes.append({
                    "scope": scope,
                    "url": r["url"],
                    "tag": r["tag"],
                    "note": r["note"],
                    "host": r["host"],
                    "code": r["code"],
                    "title": r["title"],
                    "alive": r["alive"],
                    "status": "alive" if r["alive"] == 1 else ("dead" if r["alive"] == 0 else "-")
                })
                
            conn.close()
        except Exception as e:
            print(f"[WARN] Error fetching notes for {scope}: {e}")
            
    ctx = {
        "request": request,
        "program_name": program_name,
        "meta": program_meta,
        "notes": all_notes,
        "q": q,
        "active_tab": "notes"
    }
    
    return templates.TemplateResponse("programs/notes.html", ctx)
