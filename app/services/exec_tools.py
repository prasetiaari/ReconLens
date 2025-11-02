from __future__ import annotations
import json, os, shutil
from pathlib import Path
from shutil import which
from typing import Optional

from app.core.constants import OUTPUTS_DIR  # optional kalau perlu
from app.core.pathutils import systemish_path

def python_exe() -> str:
    ve = os.environ.get("VIRTUAL_ENV")
    if ve:
        p3 = Path(ve) / "bin" / "python3"
        p  = Path(ve) / "bin" / "python"
        if p3.exists(): return str(p3)
        if p.exists():  return str(p)
    return which("python3") or which("python") or "python3"

def merged_headers_from_settings(settings: dict | None) -> dict[str, str]:
    s = settings or {}
    http = s.get("http", {}) or {}
    out: dict[str, str] = {}
    for item in (http.get("headers") or []):
        k = (item.get("key") or "").strip()
        v = (item.get("value") or "")
        if k: out[k] = v
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

def _which_with_path(tool: str, path_env: str) -> Optional[str]:
    old = os.environ.get("PATH")
    try:
        os.environ["PATH"] = path_env
        return shutil.which(tool)
    finally:
        if old is not None:
            os.environ["PATH"] = old

def resolve_external_binary(tool: str, settings: Optional[dict]) -> str:
    name = tool.lower()
    try:
        cfg_path = (settings or {}).get("tools", {}).get(name, {}).get("binary_path")
        if cfg_path and os.path.isfile(cfg_path) and os.access(cfg_path, os.X_OK):
            return cfg_path
    except Exception:
        pass

    env_key = f"RECONLENS_BIN_{name.upper()}"
    env_path = os.environ.get(env_key)
    if env_path and os.path.isfile(env_path) and os.access(env_path, os.X_OK):
        return env_path

    sys_path = systemish_path()
    cand = _which_with_path(name, sys_path)
    if cand: return cand

    cand = shutil.which(name)
    if cand: return cand

    raise ValueError(f"Executable for '{name}' not found. Set via Settings or {env_key}.")

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
    Build the CLI command for external tools and internal probes.
    """
    py = python_exe()
    out_dir = outputs_root / scope

    if tool == "gau":
        exe = resolve_external_binary("gau", settings)
        return [exe, "--verbose", "--o", str(out_dir / "urls.txt"), scope]

    if tool == "waymore":
        exe = resolve_external_binary("waymore", settings)
        return [exe, "-i", scope, "-mode", "U", "-oU", str(out_dir / "urls.txt"), "--verbose"]

    if tool == "build":
        return [py, "-m", "ReconLens", "--scope", scope,
                "--input", str(out_dir / "urls.txt"), "--out", str(out_dir)]

    if tool == "probe_subdomains":
        headers_dict = merged_headers_from_settings(settings)
        return [
            py, "-m", "ReconLens.tools.probe_subdomains",
            "--scope", scope, "--input", str(out_dir / "subdomains.txt"),
            "--outputs", str(outputs_root),
            "--concurrency", "20", "--timeout", "8",
            "--prefer-https", "--if-head-then-get",
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
        headers_dict = merged_headers_from_settings(settings)
        if module == "subdomains":
            return [
                py, "-m", "ReconLens.tools.probe_subdomains",
                "--scope", scope, "--input", str(out_dir / "subdomains.txt"),
                "--outputs", str(outputs_root),
                "--concurrency", "20", "--timeout", "8",
                "--prefer-https", "--if-head-then-get",
                "--headers-json", json.dumps(headers_dict, ensure_ascii=False),
                "--ua", headers_dict.get("User-Agent", "ReconLens/1.0 (+probe)"),
            ]
        return [
            py, "-m", "ReconLens.tools.probe_urls",
            "--scope", scope, "--outputs", str(outputs_root),
            "--input", str(input_file), "--source", mod, "--mode", "GET",
            "--concurrency", "8", "--timeout", "20",
            "--headers-json", json.dumps(headers_dict, ensure_ascii=False),
            "--ua", headers_dict.get("User-Agent", "ReconLens/1.0 (+probe)"),
        ]

    if tool == "dirsearch":
        if not host:
            raise ValueError("dirsearch requires host")
        exe = resolve_external_binary("dirsearch", settings)
        wl  = wordlists or "dicc.txt"
        from app.services.wordlists import get_wordlists_dir  # import lokal agar hindari siklus
        return [
            exe, "-u", f"https://{host}",
            "-w", f"{get_wordlists_dir()}/{wl}",
            "--format=simple", "--full-url", "--crawl", "0", "--random-agent", "--quiet",
        ]

    if tool == "subfinder":
        exe = resolve_external_binary("subfinder", settings)
        return [exe, "-d", scope, "-all", "-silent"]

    if tool == "amass":
        exe = resolve_external_binary("amass", settings)
        return [exe, "enum", "-passive", "-d", scope]

    if tool == "findomain":
        exe = resolve_external_binary("findomain", settings)
        return [exe, "--target", scope, "--quiet"]

    raise ValueError(f"unknown tool: {tool}")