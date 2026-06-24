import json
from pathlib import Path
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse

from app.deps import get_settings
from app.services.db_sync import sync_tags

router = APIRouter(tags=["Tags & Notes"])

@router.post("/{scope}/tags/note")
async def save_note(request: Request, scope: str):
    """
    Save or update a note for a specific URL.
    Payload: {"url": "https://example.com", "note": "potential injection"}
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    url = payload.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    note = payload.get("note", "").strip()

    settings = get_settings(request)
    outputs_root = Path(settings.OUTPUTS_DIR)
    scope_dir = outputs_root / scope
    cache_dir = scope_dir / "__cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    
    tags_file = cache_dir / "user_tags.json"
    
    if tags_file.exists():
        try:
            with tags_file.open("r", encoding="utf-8") as f:
                tags_data = json.load(f)
        except Exception:
            tags_data = {}
    else:
        tags_data = {}

    if url not in tags_data:
        tags_data[url] = {"tag": "star", "note": ""}
    
    tags_data[url]["note"] = note

    if not tags_data[url]["tag"] and not tags_data[url]["note"]:
        del tags_data[url]

    with tags_file.open("w", encoding="utf-8") as f:
        json.dump(tags_data, f, indent=2)

    try:
        sync_tags(outputs_root, scope, force=True)
    except Exception as e:
        print(f"[WARN] Failed to sync tags to DB: {e}")

    return JSONResponse({"ok": True, "message": "Note saved"})


@router.post("/{scope}/tags/toggle")
async def toggle_star(request: Request, scope: str):
    """
    Toggle star for a URL.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    url = payload.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    settings = get_settings(request)
    outputs_root = Path(settings.OUTPUTS_DIR)
    scope_dir = outputs_root / scope
    cache_dir = scope_dir / "__cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    
    tags_file = cache_dir / "user_tags.json"
    
    if tags_file.exists():
        try:
            with tags_file.open("r", encoding="utf-8") as f:
                tags_data = json.load(f)
        except Exception:
            tags_data = {}
    else:
        tags_data = {}

    if url in tags_data:
        if tags_data[url].get("note"):
            tags_data[url]["tag"] = ""
        else:
            del tags_data[url]
    else:
        tags_data[url] = {"tag": "star", "note": ""}

    with tags_file.open("w", encoding="utf-8") as f:
        json.dump(tags_data, f, indent=2)

    try:
        sync_tags(outputs_root, scope, force=True)
    except Exception as e:
        print(f"[WARN] Failed to sync tags to DB: {e}")

    return JSONResponse({"ok": True, "message": "Star toggled"})
