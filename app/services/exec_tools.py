from __future__ import annotations
import json, os, shutil
from pathlib import Path
from shutil import which
from typing import Any, Dict, Optional, Union

from app.core.pathutils import systemish_path

# ==========================================================
# Utility: normalize Settings (Pydantic v1/v2) into dict
# ==========================================================

def _to_cfg(settings: Optional[Union[Dict[str, Any], Any]]) -> Dict[str, Any]:
    """
    Normalize settings into a plain dict.
    Accepts:
      - dict
      - Pydantic Settings (v2 .model_dump(), v1 .dict())
      - None -> {}
    """
    if settings is None:
        return {}
    if isinstance(settings, dict):
        return settings
    if hasattr(settings, "model_dump") and callable(settings.model_dump):
        return settings.model_dump()
    if hasattr(settings, "dict") and callable(settings.dict):
        return settings.dict()
    return {}

# ==========================================================
# Python executable resolver
# ==========================================================

def python_exe() -> str:
    """Return python executable path inside venv (fallback to system python)."""
    ve = os.environ.get("VIRTUAL_ENV")
    if ve:
        p3 = Path(ve) / "bin" / "python3"
        p  = Path(ve) / "bin" / "python"
        if p3.exists(): return str(p3)
        if p.exists():  return str(p)
    return which("python3") or which("python") or "python3"

# ==========================================================
# HTTP headers merging
# ==========================================================

def merged_headers_from_settings(settings: dict | None) -> dict[str, str]:
    """Merge HTTP headers + user-agent policy from settings."""
    s = _to_cfg(settings)
    http = s.get("http", {}) or {}
    out: dict[str, str] = {}
    for item in (http.get("headers") or []):
        k = (item.get("key") or "").strip()
        v = (item.get("value") or "")
        if k:
            out[k] = v

    ua_mode  = ((http.get("user_agent") or {}).get("mode") or "default").lower()
    ua_value = (http.get("user_agent") or {}).get("value") or ""
    if not any(k.lower() == "user-agent" for k in out.keys()):
        if ua_mode == "custom" and ua_value.strip():
            out["User-Agent"] = ua_value.strip()
        elif ua_mode == "random":
            out["User-Agent"] = "ReconLens/1.0 (+random-UA-placeholder)"
        else:
            out["User-Agent"] = "ReconLens/1.0 (+probe)"
    return out

# ==========================================================
# External binary resolver
# ==========================================================

def _which_with_path(tool: str, path_env: str) -> Optional[str]:
    """Try locating a binary using a custom PATH (used for Homebrew/Linux)."""
    old = os.environ.get("PATH")
    try:
        os.environ["PATH"] = path_env
        return shutil.which(tool)
    finally:
        if old is not None:
            os.environ["PATH"] = old

def resolve_external_binary(tool: str, settings: Optional[dict]) -> str:
    """Locate a binary either from settings, environment, or PATH."""
    cfg = _to_cfg(settings)
    name = tool.lower()

    # 1. From settings.tools.<tool>.binary_path
    try:
        cfg_path = (cfg.get("tools", {}).get(name, {}).get("binary_path"))
        if cfg_path and os.path.isfile(cfg_path) and os.access(cfg_path, os.X_OK):
            return cfg_path
    except Exception:
        pass

    # 2. From environment variable
    env_key = f"RECONLENS_BIN_{name.upper()}"
    env_path = os.environ.get(env_key)
    if env_path and os.path.isfile(env_path) and os.access(env_path, os.X_OK):
        return env_path

    # 3. From system PATH (Homebrew / usr/local / usr/bin)
    sys_path = systemish_path()
    cand = _which_with_path(name, sys_path)
    if cand: return cand

    # 4. Fallback to current PATH
    cand = shutil.which(name)
    if cand: return cand

    raise ValueError(f"Executable for '{name}' not found. Set via Settings or {env_key}.")

# ==========================================================
# Command builder for all tools
# ==========================================================

def build_tool_cmd(
    tool: str,
    scope: str,
    outputs_root: Path,
    *,
    module: str | None = None,
    host: str | None = None,
    wordlists: str | None = None,
    settings: Optional[dict] = None,
) -> list[str]:
    """
    Build the CLI command for external tools and internal ReconLens modules.
    Safe to call with either dict or Settings object.
    """
    cfg = _to_cfg(settings)
    py = python_exe()
    out_dir = outputs_root / scope

    # --- URL collectors ---
    if tool == "gau":
        exe = resolve_external_binary("gau", cfg)
        return [exe, "--verbose", "--o", str(out_dir / "urls.txt"), scope]

    if tool == "waymore":
        exe = resolve_external_binary("waymore", cfg)
        return [exe, "-i", scope, "-mode", "U", "-oU", str(out_dir / "urls.txt"), "--verbose"]

    # --- internal build module ---
    if tool == "build":
        return [py, "-m", "ReconLens",
                "--scope", scope,
                "--input", str(out_dir / "urls.txt"),
                "--out", str(out_dir)]

    # --- probing ---
    if tool == "probe_subdomains":
        headers_dict = merged_headers_from_settings(cfg)
        return [
            py, "-m", "ReconLens.tools.probe_subdomains",
            "--scope", scope,
            "--input", str(out_dir / "subdomains.txt"),
            "--outputs", str(outputs_root),
            "--concurrency", "20",
            "--timeout", "8",
            "--prefer-https",
            "--if-head-then-get",
            "--headers-json", json.dumps(headers_dict, ensure_ascii=False),
            "--ua", headers_dict.get("User-Agent", "ReconLens/1.0 (+probe)"),
        ]

    if tool == "probe_module":
        if not module:
            raise ValueError("probe_module requires module name")
        mod = module.lower()
        candidates = out_dir / f"{mod}_candidates.txt"
        fallback   = out_dir / f"{mod}.txt"
        input_file = candidates if candidates.exists() else fallback
        headers_dict = merged_headers_from_settings(cfg)
        if module == "subdomains":
            return [
                py, "-m", "ReconLens.tools.probe_subdomains",
                "--scope", scope,
                "--input", str(out_dir / "subdomains.txt"),
                "--outputs", str(outputs_root),
                "--concurrency", "20",
                "--timeout", "8",
                "--prefer-https",
                "--if-head-then-get",
                "--headers-json", json.dumps(headers_dict, ensure_ascii=False),
                "--ua", headers_dict.get("User-Agent", "ReconLens/1.0 (+probe)"),
            ]
        return [
            py, "-m", "ReconLens.tools.probe_urls",
            "--scope", scope,
            "--outputs", str(outputs_root),
            "--input", str(input_file),
            "--source", mod,
            "--mode", "GET",
            "--concurrency", "8",
            "--timeout", "20",
            "--headers-json", json.dumps(headers_dict, ensure_ascii=False),
            "--ua", headers_dict.get("User-Agent", "ReconLens/1.0 (+probe)"),
        ]

    # --- dirsearch ---
    if tool == "dirsearch":
        if not host:
            raise ValueError("dirsearch requires host")
        exe = resolve_external_binary("dirsearch", cfg)
        wl  = wordlists or "dicc.txt"
        from app.services.wordlists import get_wordlists_dir  # local import avoids cycle
        return [
            exe, "-u", f"https://{host}",
            "-w", f"{get_wordlists_dir()}/{wl}",
            "--format=simple",
            "--full-url",
            "--crawl", "0",
            "--random-agent",
            "--quiet",
        ]

    # --- passive subdomain collectors ---
    if tool == "subfinder":
        exe = resolve_external_binary("subfinder", cfg)
        return [exe, "-d", scope, "-all", "-silent"]

    if tool == "amass":
        exe = resolve_external_binary("amass", cfg)
        return [exe, "enum", "-passive", "-d", scope]

    if tool == "findomain":
        exe = resolve_external_binary("findomain", cfg)
        return [exe, "--target", scope, "--quiet"]

    raise ValueError(f"Unknown tool: {tool}")