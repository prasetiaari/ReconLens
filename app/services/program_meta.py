import json
from pathlib import Path
from typing import Dict, Any

def get_program_meta_file(outputs_dir: Path) -> Path:
    return outputs_dir / "program_meta.json"

def load_program_meta(outputs_dir: Path) -> dict:
    p = get_program_meta_file(outputs_dir)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_program_meta(outputs_dir: Path, data: dict):
    p = get_program_meta_file(outputs_dir)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")

def update_program_meta(outputs_dir: Path, program: str, meta: Dict[str, Any]):
    data = load_program_meta(outputs_dir)
    if program not in data:
        data[program] = {}
    
    # Update fields provided (keep others intact)
    for k, v in meta.items():
        data[program][k] = v
        
    save_program_meta(outputs_dir, data)
