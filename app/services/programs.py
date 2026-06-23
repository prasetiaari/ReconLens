from __future__ import annotations
import json
from pathlib import Path

def get_programs_file(outputs_dir: Path) -> Path:
    return outputs_dir / "programs.json"

def load_programs(outputs_dir: Path) -> dict:
    p = get_programs_file(outputs_dir)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_programs(outputs_dir: Path, data: dict):
    p = get_programs_file(outputs_dir)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")

def ensure_program(outputs_dir: Path, name: str):
    data = load_programs(outputs_dir)
    if name not in data:
        data[name] = []
        save_programs(outputs_dir, data)

def move_scope(outputs_dir: Path, scope: str, to_program: str):
    data = load_programs(outputs_dir)
    
    # Remove scope from all existing programs
    for prog_name, scopes in data.items():
        if scope in scopes:
            scopes.remove(scope)
    
    # Add to the new program
    if to_program not in data:
        data[to_program] = []
    
    if scope not in data[to_program]:
        data[to_program].append(scope)
        
    save_programs(outputs_dir, data)
