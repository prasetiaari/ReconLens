# app/services/ai_command.py
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from uuid import uuid4

CACHE_DIR_NAME = "__cache"
HISTORY_FILE = "ai_command.jsonl"

def _cache_dir(outputs_root: Path, scope: str) -> Path:
    d = outputs_root / scope / CACHE_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d

def append_history(outputs_root: Path, scope: str, role: str, text: str) -> None:
    p = _cache_dir(outputs_root, scope) / HISTORY_FILE
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"id": str(uuid4()), "role": role, "text": text}) + "\n")

def read_history(outputs_root: Path, scope: str, limit: int = 200) -> List[Dict[str,Any]]:
    p = _cache_dir(outputs_root, scope) / HISTORY_FILE
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8").splitlines()
    items = [json.loads(l) for l in lines[-limit:]]
    return items

# Very simple rule-based parser: returns a plan
def parse_prompt_to_plan(prompt: str, scope: str) -> Dict[str, Any]:
    # normalize
    s = prompt.lower().strip()
    # simple heuristics
    if "subdomain" in s and "aktif" in s or "alive" in s:
        # plan: use current subdomains file -> httprobe
        return {
            "version": 1,
            "steps": [
                {
                    "id": "probe1",
                    "tool": "httprobe",
                    "args": {"concurrency": 50},
                    "targets": {"from": "subdomains.txt"},
                    "outputs": ["ai_command/alive.txt"]
                }
            ],
            "note": "parsed by rule-based parser"
        }
    if s.startswith("dirsearch") or "dirsearch" in s:
        # naive parse: might include host or wordlist
        return {
            "version": 1,
            "steps": [
                {
                    "id": "dir1",
                    "tool": "dirsearch",
                    "args": {"wordlist": "default.txt", "rate": 50},
                    "targets": {"hosts": [scope]},
                    "outputs": ["ai_command/dirsearch.jsonl"]
                }
            ]
        }
    # fallback: ask to clarify
    return {"version": 1, "steps": [], "error": "Sorry, couldn't parse intent. Try 'tampilkan seluruh subdomain yg aktif' or 'dirsearch for example.com'."}
