import os
from pathlib import Path
import shutil

def split_path(pathstr: str) -> list[str]:
    """Split PATH-style strings into list items."""
    return [p for p in (pathstr or "").split(os.pathsep) if p]

def without_venv_bin(path_list: list[str]) -> list[str]:
    """Remove the active venv/bin path from PATH components."""
    ve = os.environ.get("VIRTUAL_ENV")
    if not ve:
        return path_list
    ve_bin = str(Path(ve) / "bin")
    return [p for p in path_list if os.path.abspath(p) != os.path.abspath(ve_bin)]

def systemish_path() -> str:
    """Return a cleaned PATH, prioritizing system-wide binaries over venv/bin."""
    base = without_venv_bin(split_path(os.environ.get("PATH", "")))
    prefer = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    ordered = [p for p in prefer if os.path.isdir(p)] + base
    seen, uniq = set(), []
    for p in ordered:
        if p not in seen:
            uniq.append(p); seen.add(p)
    return os.pathsep.join(uniq)