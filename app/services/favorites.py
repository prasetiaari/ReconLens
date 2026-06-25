from __future__ import annotations
import json
from pathlib import Path

def get_favorites_file(outputs_dir: Path) -> Path:
    return outputs_dir / "favorites.json"

def load_favorites(outputs_dir: Path) -> set[str]:
    p = get_favorites_file(outputs_dir)
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return set(data)
        return set()
    except Exception:
        return set()

def toggle_favorite(outputs_dir: Path, scope: str) -> bool:
    favs = load_favorites(outputs_dir)
    is_fav = False
    if scope in favs:
        favs.remove(scope)
    else:
        favs.add(scope)
        is_fav = True
        
    p = get_favorites_file(outputs_dir)
    p.write_text(json.dumps(list(favs), indent=2), encoding="utf-8")
    return is_fav
