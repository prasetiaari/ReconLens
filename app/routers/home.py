from __future__ import annotations
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from app.deps import get_settings, get_templates
from app.services.targets import list_scopes

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    from app.services.programs import load_programs
    
    settings = get_settings(request)
    templates = get_templates(request)
    scopes = list_scopes(settings.OUTPUTS_DIR)

    # Load persistent grouping
    saved_programs = load_programs(settings.OUTPUTS_DIR)
    
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
            
    # Filter out empty groups, but keep Default if it's the only one
    groups = {k: v for k, v in groups.items() if v or k == "Default" or k in saved_programs}

    return templates.TemplateResponse("layout/home.html", {
        "request": request,
        "scopes": scopes,
        "groups": groups,
    })
