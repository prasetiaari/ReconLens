from __future__ import annotations
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from app.deps import get_settings, get_templates
from app.services.targets import list_scopes

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    from app.services.programs import load_programs
    from app.services.favorites import load_favorites
    
    settings = get_settings(request)
    templates = get_templates(request)
    scopes = list_scopes(settings.OUTPUTS_DIR)

    # Load persistent grouping
    saved_programs = load_programs(settings.OUTPUTS_DIR)
    favorites = load_favorites(settings.OUTPUTS_DIR)
    
    groups = {
        "Default": []
    }
    
    # Track which scopes are already assigned
    assigned_scopes = set()
    
    # Populate groups from saved_programs, keeping only existing scopes
    for prog_name, prog_scopes in saved_programs.items():
        if prog_name not in groups:
            groups[prog_name] = []
        for s in prog_scopes:
            if s in scopes:
                groups[prog_name].append(s)
                assigned_scopes.add(s)
                
    # Any scope not assigned goes to Default
    for s in scopes:
        if s not in assigned_scopes:
            groups["Default"].append(s)
            
    # Sort each group: Favorites first, then alphabetically
    for prog_name in groups:
        groups[prog_name].sort(key=lambda x: (x not in favorites, x))

    # Calculate quick stats for UI
    from app.routers.targets.utils import count_lines, safe_json_load
    
    scope_stats = {}
    program_stats = {}
    
    for prog_name, prog_scopes in groups.items():
        p_subs = 0
        p_urls = 0
        for s in prog_scopes:
            target_dir = settings.OUTPUTS_DIR / s
            
            subs = count_lines(target_dir / "subdomains.txt")
            urls = count_lines(target_dir / "urls.txt")
            
            meta = safe_json_load(target_dir / "meta.json")
            last_scans = meta.get("last_scans", {})
            last_scan = max(last_scans.values()) if last_scans else None
            
            # Convert ISO string to something shorter if possible
            last_scan_short = ""
            if last_scan:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(last_scan.replace('Z', '+00:00'))
                    last_scan_short = dt.strftime("%b %d, %Y")
                except:
                    last_scan_short = last_scan.split('T')[0]

            scope_stats[s] = {
                "subs": subs,
                "urls": urls,
                "last_scan": last_scan_short
            }
            p_subs += subs
            p_urls += urls
            
        program_stats[prog_name] = {
            "subs": p_subs,
            "urls": p_urls
        }

    from app.services.program_meta import load_program_meta
    program_meta = load_program_meta(settings.OUTPUTS_DIR)

    return templates.TemplateResponse("layout/home.html", {
        "request": request,
        "scopes": scopes,
        "groups": groups,
        "favorites": favorites,
        "scope_stats": scope_stats,
        "program_stats": program_stats,
        "program_meta": program_meta,
    })
