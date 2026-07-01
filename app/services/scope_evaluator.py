import json
import re
from pathlib import Path
from typing import List, Dict

def get_scope_file(target_dir: Path) -> Path:
    return target_dir / "scope.json"

def load_scope_rules(target_dir: Path) -> Dict[str, List[str]]:
    sf = get_scope_file(target_dir)
    if not sf.exists():
        return {"in_scope": [], "out_of_scope": []}
    try:
        data = json.loads(sf.read_text(encoding="utf-8"))
        return {
            "in_scope": data.get("in_scope", []),
            "out_of_scope": data.get("out_of_scope", [])
        }
    except Exception:
        return {"in_scope": [], "out_of_scope": []}

def save_scope_rules(target_dir: Path, in_scope: List[str], out_of_scope: List[str]):
    sf = get_scope_file(target_dir)
    data = {
        "in_scope": [x.strip() for x in in_scope if x.strip()],
        "out_of_scope": [x.strip() for x in out_of_scope if x.strip()]
    }
    sf.write_text(json.dumps(data, indent=2), encoding="utf-8")

def _compile_pattern(pattern: str) -> re.Pattern:
    # Convert wildcard '*' to regex '.*' and escape dots
    regex_str = pattern.replace(".", r"\.").replace("*", r".*")
    # Require exact match for safety
    return re.compile(f"^{regex_str}$", re.IGNORECASE)

def is_in_scope(hostname_or_url: str, rules: Dict[str, List[str]]) -> bool:
    if not hostname_or_url:
        return False
        
    # Extract host if it's a full URL
    host = hostname_or_url
    if "://" in host:
        from urllib.parse import urlparse
        try:
            host = urlparse(host).hostname or host
        except Exception:
            pass
            
    # Remove port if present
    host = host.split(":")[0]
    
    # 1. Check out_of_scope first (DENY is stronger than ALLOW)
    for rule in rules.get("out_of_scope", []):
        try:
            pat = _compile_pattern(rule)
            if pat.match(host):
                return False
        except Exception:
            continue
            
    # 2. Check in_scope
    in_scope_rules = rules.get("in_scope", [])
    if not in_scope_rules:
        # If no in-scope rules defined, default to ALLOW ALL
        # (Assuming the initial recon output is the implicit scope)
        return True
        
    for rule in in_scope_rules:
        try:
            pat = _compile_pattern(rule)
            if pat.match(host):
                return True
        except Exception:
            continue
            
    # If in-scope rules exist but no match, it's out of scope
    return False

def get_scope_stats(items: List[str], rules: Dict[str, List[str]]) -> Dict[str, int]:
    """Helper to quickly check a list of items and return count of in_scope/oos."""
    in_scope = 0
    oos = 0
    for item in items:
        if is_in_scope(item, rules):
            in_scope += 1
        else:
            oos += 1
    return {"in_scope": in_scope, "oos": oos}
