from pathlib import Path
import json
from datetime import datetime, timezone
from app.core.constants import OUTPUTS_DIR

def gather_stats(scope: str):
    """
    Collect statistics for a given target scope.
    """
    out_dir = OUTPUTS_DIR / scope
    if not out_dir.exists():
        return {"stats": [], "urls_count": 0, "dash": {}}

    def read_text_lines(p: Path):
        try:
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                return sum(1 for _ in f)
        except Exception:
            return 0

    def safe_json_load(p: Path):
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def stat_file(p: Path):
        if not p.exists():
            return 0, 0
        try:
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                lines = sum(1 for _ in f)
            return lines, p.stat().st_size
        except Exception:
            return 0, p.stat().st_size if p.exists() else 0

    urls_path = out_dir / "urls.txt"
    urls_count = read_text_lines(urls_path)

    out = []
    for p in sorted(out_dir.glob("*.txt")):
        name = p.stem
        if name == "urls":
            continue
        lines, size = stat_file(p)
        row = {"module": name, "file": p.name, "lines": lines, "size_bytes": size}
        out.append(row)

    meta = safe_json_load(out_dir / "meta.json")
    dash = {
        "totals": meta.get("totals", {}),
        "status_counts": meta.get("status_counts", {}),
        "ctypes": meta.get("ctypes", {}),
        "last_probe_iso": (meta.get("last_scans") or {}).get("probe", None),
        "last_scans": meta.get("last_scans", {}),
    }

    return {"stats": out, "urls_count": urls_count, "dash": dash}