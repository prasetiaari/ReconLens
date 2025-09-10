# urls_parser/core/config.py
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

def load_config(path: str | None) -> Dict[str, Any]:
    """
    Load YAML config menjadi dict. 
    - Jika path None/empty → kembalikan {}.
    - Jika file tidak ada → raise FileNotFoundError.
    - Jika PyYAML belum terpasang → berikan error yang ramah.
    """
    if not path:
        return {}
    p = Path(path)
    print(p)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {p}")

    try:
        import yaml  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "PyYAML belum terpasang. Install dengan: pip install pyyaml"
        ) from e

    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    if not isinstance(data, dict):
        raise ValueError(f"Config root harus berupa object/dict, bukan {type(data)}")

    return data
