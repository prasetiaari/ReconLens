# app/routers/targets_api.py
from __future__ import annotations
import json, re, time
from pathlib import Path
from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import PlainTextResponse

from app.deps import get_settings

router = APIRouter(prefix="/targets/api", tags=["targets-api"])

# Regex domain sederhana (tanpa dep eksternal)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)

def normalize_scope(raw: str) -> str:
    v = (raw or "").strip().lower()
    # kalau user paste URL, ambil host-nya
    if v.startswith("http://") or v.startswith("https://"):
        from urllib.parse import urlparse
        try:
            v = urlparse(v).hostname or v
        except Exception:
            pass
    # drop apa pun setelah slash
    v = v.split("/", 1)[0]
    # drop port jika ada
    v = v.split(":", 1)[0]
    return v

@router.post("/add")
def add_target(scope: str = Form(...), request: Request = None):
    from pathlib import Path
    import json, time

    settings   = get_settings(request)
    scope_norm = normalize_scope(scope)

    # Validasi domain
    if not DOMAIN_RE.match(scope_norm):
        return PlainTextResponse("Invalid domain format.", status_code=400)

    base: Path   = settings.OUTPUTS_DIR
    target_dir   = base / scope_norm

    if target_dir.exists():
        resp = PlainTextResponse("Target already exists.", status_code=200)
        resp.headers["HX-Redirect"] = f"/targets/{scope_norm}"
        return resp

    try:
        # Struktur minimal (NO legacy placeholders)
        (target_dir / "__cache").mkdir(parents=True, exist_ok=True)
        (target_dir / "__jobs__").mkdir(parents=True, exist_ok=True)
        (target_dir / "raw").mkdir(parents=True, exist_ok=True)
        (target_dir / "classified").mkdir(parents=True, exist_ok=True)

        meta = {
            "scope": scope_norm,
            "created_at": int(time.time()),
            "created_by": "ui",
            "notes": "",
            "last_scans": {},  # slot baru untuk timestamp tools
        }
        (target_dir / "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    except Exception as e:
        return PlainTextResponse(f"Failed to create target: {e}", status_code=500)

    resp = PlainTextResponse("Created", status_code=201)
    resp.headers["HX-Redirect"] = f"/targets/{scope_norm}"
    return resp
