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
    Normalize settings into a plain dict and merge with dynamic user settings.
    Accepts:
      - dict
      - Pydantic Settings (v2 .model_dump(), v1 .dict())
      - None -> {}
    """
    if settings is None:
        out = {}
    elif isinstance(settings, dict):
        out = dict(settings)
    elif hasattr(settings, "model_dump") and callable(settings.model_dump):
        out = settings.model_dump()
    elif hasattr(settings, "dict") and callable(settings.dict):
        out = settings.dict()
    else:
        out = {}

    try:
        from app.core.config_store import load_settings
        user = load_settings()
        for k, v in user.items():
            if k not in out or not out[k]:
                out[k] = v
            elif isinstance(v, dict) and isinstance(out[k], dict):
                for sk, sv in v.items():
                    if sk not in out[k] or not out[k][sk]:
                        out[k][sk] = sv
    except Exception:
        pass

    return out

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

    # 1. From settings.tools.<tool>.binary_path or settings.tools.<tool>_binary_path
    try:
        cfg_path = (cfg.get("tools", {}).get(name, {}).get("binary_path"))
        if cfg_path and os.path.isfile(cfg_path) and os.access(cfg_path, os.X_OK):
            return cfg_path
    except Exception:
        pass

    try:
        cfg_path = (cfg.get("tools", {}).get(f"{name}_binary_path"))
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
    dirsearch_outfile: Optional[Path] = None,
    custom_cmd: str | None = None,
    probe_mode: str = "HEAD",
    only_alive: bool = False,
) -> list[str]:
    """
    Build the CLI command for external tools and internal ReconLens modules.
    Safe to call with either dict or Settings object.
    """
    cfg = _to_cfg(settings)
    py = python_exe()
    out_dir = outputs_root / scope

    # --- Custom Bash ---
    if tool == "custom_bash" and custom_cmd:
        # Wrap the custom command in bash -c and run it in the target directory using absolute path
        return ["/bin/bash", "-c", f"cd {out_dir} && {custom_cmd}"]

    # --- URL collectors ---
    if tool == "gau":
        exe = resolve_external_binary("gau", cfg)
        cmd = [exe, "--verbose"]
        proxy_cfg = cfg.get("http", {}).get("proxy", {})
        if proxy_cfg.get("enabled") and proxy_cfg.get("url"):
            cmd += ["--proxy", proxy_cfg.get("url").strip()]
        cmd.append(scope)
        return cmd

    if tool == "waymore":
        exe = resolve_external_binary("waymore", cfg)
        
        # Build custom config with API keys from settings
        urlscan_api = cfg.get("tools", {}).get("urlscan_api", "").strip()
        virustotal_api = cfg.get("tools", {}).get("virustotal_api", "").strip()
        
        # Try to read base waymore config
        base_config_path = Path.home() / ".config" / "waymore" / "config.yml"
        if base_config_path.exists():
            config_content = base_config_path.read_text(encoding="utf-8", errors="ignore")
        else:
            # Fallback template
            config_content = (
                "FILTER_CODE: 404,301,302\n"
                "FILTER_MIME: text/css,image/jpeg,image/jpg,image/png,image/svg+xml,image/gif,image/tiff,image/webp,image/bmp,image/vnd,image/x-icon,image/vnd.microsoft.icon,font/ttf,font/woff,font/woff2,font/x-woff2,font/x-woff,font/otf,audio/mpeg,audio/wav,audio/webm,audio/aac,audio/ogg,audio/wav,audio/webm,video/mp4,video/mpeg,video/webm,video/ogg,video/mp2t,video/webm,video/x-msvideo,video/x-flv,application/font-woff,application/font-woff2,application/x-font-woff,application/x-font-woff2,application/vnd.ms-fontobject,application/font-sfnt,application/vnd.android.package-archive,binary/octet-stream,application/octet-stream,application/pdf,application/x-font-ttf,application/x-font-otf,video/webm,video/3gpp,application/font-ttf,audio/mp3,audio/x-wav,image/pjpeg,audio/basic,application/font-otf,application/x-ms-application,application/x-msdownload,video/x-ms-wmv,image/x-png,video/quicktime,image/x-ms-bmp,font/opentype,application/x-font-opentype,application/x-woff,audio/aiff\n"
                "FILTER_URL: .css,.jpg,.jpeg,.png,.svg,.img,.gif,.mp4,.flv,.ogv,.webm,.webp,.mov,.mp3,.m4a,.m4p,.scss,.tif,.tiff,.ttf,.otf,.woff,.woff2,.bmp,.ico,.eot,.htc,.rtf,.swf,.image,/image,/img,/css,/wp-json,/wp-content,/wp-includes,/theme,/audio,/captcha,/font,node_modules,/jquery,/bootstrap\n"
                "FILTER_KEYWORDS: admin,login,logon,signin,signup,register,registration,dash,portal,ftp,panel,.js,api,robots.txt,graph,gql,config,backup,debug,db,database,git,cgi-bin,swagger,zip,.rar,tar.gz,internal,jira,jenkins,confluence,atlassian,okta,corp,upload,delete,email,sql,create,edit,test,temp,cache,wsdl,log,payment,setting,mail,file,redirect,chat,billing,doc,trace,ftp,gateway,import,proxy,dev,stage,stg,uat,sonar.ci.,.cp.\n"
                "URLSCAN_API_KEY:\n"
                "VIRUSTOTAL_API_KEY:\n"
                "CONTINUE_RESPONSES_IF_PIPED: True\n"
                "WEBHOOK_DISCORD: YOUR_WEBHOOK\n"
                "DEFAULT_OUTPUT_DIR:\n"
            )

        # Replace or add keys
        new_lines = []
        has_urlscan = False
        has_virustotal = False
        for line in config_content.splitlines():
            if line.startswith("URLSCAN_API_KEY:"):
                new_lines.append(f"URLSCAN_API_KEY: {urlscan_api}")
                has_urlscan = True
            elif line.startswith("VIRUSTOTAL_API_KEY:"):
                new_lines.append(f"VIRUSTOTAL_API_KEY: {virustotal_api}")
                has_virustotal = True
            else:
                new_lines.append(line)
        
        if not has_urlscan:
            new_lines.append(f"URLSCAN_API_KEY: {urlscan_api}")
        if not has_virustotal:
            new_lines.append(f"VIRUSTOTAL_API_KEY: {virustotal_api}")

        # Write to outputs/<scope>/raw/waymore_config.yml
        raw_dir = out_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        custom_config_path = raw_dir / "waymore_config.yml"
        custom_config_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

        return [exe, "-i", scope, "-mode", "U", "-oU", str(out_dir / "urls.txt"), "-c", str(custom_config_path), "--verbose"]

    if tool == "urlfinder":
        exe = resolve_external_binary("urlfinder", cfg)
        return [exe, "-d", scope, "-all", "-o", str(out_dir / "urls.txt")]

    # --- internal build module ---
    if tool == "build":
        main_py = Path(__file__).parent.parent.parent / "__main__.py"
        return [py, str(main_py),
                "--scope", scope,
                "--input", str(out_dir / "urls.txt"),
                "--out", str(out_dir)]

    # --- probing ---
    if tool == "probe_subdomains":
        headers_dict = merged_headers_from_settings(cfg)
        script_py = Path(__file__).parent.parent.parent / "tools" / "probe_subdomains.py"
        return [
            py, str(script_py),
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
        
        probe_sub_py = Path(__file__).parent.parent.parent / "tools" / "probe_subdomains.py"
        probe_urls_py = Path(__file__).parent.parent.parent / "tools" / "probe_urls.py"
        
        if module == "subdomains":
            return [
                py, str(probe_sub_py),
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
        cmd = [
            py, str(probe_urls_py),
            "--scope", scope,
            "--outputs", str(outputs_root),
            "--input", str(input_file),
            "--source", mod,
            "--mode", probe_mode,
            "--concurrency", "8",
            "--timeout", "20",
            "--headers-json", json.dumps(headers_dict, ensure_ascii=False),
            "--ua", headers_dict.get("User-Agent", "ReconLens/1.0 (+probe)"),
        ]
        if only_alive:
            cmd.append("--only-alive")
        return cmd

    # --- dirsearch ---
    if tool == "dirsearch":
        if not host:
            raise ValueError("dirsearch requires host")
        exe = resolve_external_binary("dirsearch", cfg)
        wl  = wordlists or "dicc.txt"
        from app.services.wordlists import get_wordlists_dir  # local import avoids cycle
        cmd = [
            exe, "-u", f"https://{host}",
            "-w", f"{get_wordlists_dir()}/{wl}",
            "--format=simple",
            "--full-url",
            "--crawl", "0",
            "--random-agent",
            "--quiet",
        ]
        # Write results to a controlled file under outputs/, so dirsearch
        # doesn't create its own folders elsewhere.
        if dirsearch_outfile:
            cmd += ["-o", str(dirsearch_outfile)]
        return cmd

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

    if tool == "nuclei_takeover":
        exe = resolve_external_binary("nuclei", cfg)
        return [
            exe,
            "-tags", "takeover",
            "-l", str(out_dir / "subdomains.txt"),
            "-o", str(out_dir / "takeovers.txt"),
            "-silent"
        ]

    if tool == "subzy_takeover":
        exe = resolve_external_binary("subzy", cfg)
        return [
            exe,
            "run",
            "--targets", str(out_dir / "subdomains.txt"),
            "--hide_fails"
        ]

    if tool == "subjack_takeover":
        exe = resolve_external_binary("subjack", cfg)
        return [
            exe,
            "-w", str(out_dir / "subdomains.txt"),
            "-t", "100",
            "-timeout", "30",
            "-ssl",
            "-o", str(out_dir / "takeovers.txt")
        ]

    raise ValueError(f"Unknown tool: {tool}")