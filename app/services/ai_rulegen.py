# app/services/ai_rulegen.py
from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import random
import re
import time
import requests
import collections

import os
DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_TIMEOUT = 60  # detik

def _get_ollama_base_url() -> str:
    env_host = os.environ.get("OLLAMA_HOST")
    if env_host:
        return env_host.rstrip("/")
    if Path("/.dockerenv").exists():
        return "http://host.docker.internal:11434"
    return "http://localhost:11434"

# ============================
# Path helpers
# ============================
def _outputs_scope_dir(outputs_root: Path, scope: str) -> Path:
    return outputs_root / scope


def _cache_dir(outputs_root: Path, scope: str) -> Path:
    d = _outputs_scope_dir(outputs_root, scope) / "__cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _debug_path(outputs_root: Path, scope: str, name: str) -> Path:
    dbg = _cache_dir(outputs_root, scope) / "ai_debug"
    dbg.mkdir(parents=True, exist_ok=True)
    return dbg / name


def _urls_path(outputs_root: Path, scope: str) -> Path:
    return _outputs_scope_dir(outputs_root, scope) / "urls.txt"


def _generated_rules_path(outputs_root: Path, scope: str) -> Path:
    return _cache_dir(outputs_root, scope) / "ai_rules.generated.json"


# ============================
# URLs loading / sampling
# ============================
def load_urls(outputs_root: Path, scope: str, limit: Optional[int] = None) -> List[str]:
    p = _urls_path(outputs_root, scope)
    if not p.exists():
        return []
    out: List[str] = []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            s = (ln or "").strip()
            if not s:
                continue
            out.append(s)
            if limit and len(out) >= limit:
                break
    return out


def sample_urls(urls: List[str], sample_size: int = 200) -> List[str]:
    if not urls:
        return []
    if sample_size <= 0 or sample_size >= len(urls):
        return urls[:1000]  # guard
    random.seed(42)
    return random.sample(urls, sample_size)


# ============================
# Prompts for RULE generation
# ============================
def _build_prompt(urls: List[str]) -> str:
    examples = [
        {
            "id": "custom-high-archives",
            "label": "HIGH",
            "reason": "Backup/source archives exposed",
            "pattern": r"\.(?:zip|rar|7z|tar|tgz|tar\.gz|gz|bz2)$",
            "code_in": [200, 206],
        },
        {
            "id": "custom-high-db-dumps",
            "label": "HIGH",
            "reason": "Database dumps exposed",
            "pattern": r"\.(?:sql|sqlite|db|dump)(?:\.(?:gz|bz2|zip))?$",
            "code_in": [200, 206],
        },
        {
            "id": "custom-medium-admin",
            "label": "MEDIUM",
            "reason": "Admin panels or dashboards",
            "pattern": r"/(?:admin|administrator|wp-admin|dashboard)(?:/|$)",
            "code_in": [200, 302, 401, 403],
        },
        {
            "id": "custom-medium-upload",
            "label": "MEDIUM",
            "reason": "Upload or file manager directories",
            "pattern": r"/(?:uploads?|filemanager|userfiles?)(?:/|$)",
            "code_in": [200, 403],
        },
        {
            "id": "custom-low-config",
            "label": "LOW",
            "reason": "Config or environment files",
            "pattern": r"/(?:\.env|config\.php|settings\.json)$",
            "code_in": [200, 403],
        },
    ]

    urls_block = "\n".join(urls[:300])  # batasi biar prompt tidak kepanjangan

    return (
        "You are a security assistant. Your task: generate concise REGEX rules to detect risky HTTP paths "
        "from the given URLs.\n\n"
        "⚠️ Requirements:\n"
        "- Provide BETWEEN 8 and 15 rules (not less).\n"
        "- Each rule must target a DIFFERENT risk category (e.g., archives, db dumps, admin panels, uploads, configs, logs, source code, etc).\n"
        "- Output MUST be a VALID JSON ARRAY only (no text, no markdown, no explanations).\n"
        "- Each object must have: id, label (HIGH/MEDIUM/LOW/INFO), reason, pattern, code_in.\n"
        "- Use Python-style regex; escape dots; use non-capturing groups (?: ).\n"
        "- Avoid duplicates or overly broad patterns (e.g., just '.*').\n\n"
        "Here are some examples of valid rules:\n"
        f"{json.dumps(examples, ensure_ascii=False, indent=2)}\n\n"
        "=== URL SAMPLES (for inspiration) ===\n"
        f"{urls_block}\n\n"
        "=== OUTPUT JSON ARRAY STARTS BELOW ==="
    )


def _clean_html_for_llm(content: str) -> str:
    if not content:
        return ""
    t = content
    # Replace common block elements with newlines or spaces to preserve readability
    t = re.sub(r'</?(div|p|li|ul|ol|br|h[1-6]|tr|pre|code)[^>]*>', '\n', t)
    t = re.sub(r'<[^>]+>', '', t)
    # Decode basic HTML entities to keep context clean
    t = t.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("&quot;", '"').replace("&#39;", "'").replace("&apos;", "'")
    # Normalize multiple newlines/whitespaces
    t = re.sub(r'\n\s*\n+', '\n', t)
    return t.strip()


# ============================
# Ollama call (multi-mode)
# ============================
def _call_ollama(
    prompt: str,
    model: str,
    timeout: int,
    temperature: float = 0.5,
    mode: str = "rules",  # "rules" | "command"
    history: list = None,
) -> Any:
    """
    mode="rules"   : strict JSON array of rule objects
    mode="command" : strict JSON for chat/plan/confirm/revise
    """
    from app.core.config_store import load_settings

    # Load active runtime settings
    try:
        settings = load_settings()
        ai_cfg = settings.get("ai", {})
        source = ai_cfg.get("source") or "local"
        cloud_endpoint = ai_cfg.get("endpoint") or "https://api.openai.com/v1/chat/completions"
        cloud_api_key = ai_cfg.get("api_key") or ""
        cloud_model = ai_cfg.get("model") or "gpt-3.5-turbo"
        ctx_size = ai_cfg.get("ctx_size", 10)
        custom_system_prompt = ai_cfg.get("system_prompt", "")
    except Exception:
        source = "local"
        cloud_endpoint = "https://api.openai.com/v1/chat/completions"
        cloud_api_key = ""
        cloud_model = "gpt-3.5-turbo"
        ctx_size = 10
        custom_system_prompt = ""

    source = source.strip().lower()

    if mode == "rules":
        system_msg = (
            "You are a strict JSON generator. "
            "Always return a JSON array of rule objects, and nothing else. "
            "Never include wrapper keys like 'results', 'data', or 'summary'. "
            "No markdown, no explanations."
        )
    elif mode == "command":
        if custom_system_prompt:
            if "Available Tools:" not in custom_system_prompt:
                try:
                    tools_part = LLM_SYSTEM_MSG.split("Available Tools:", 1)[1]
                    system_msg = custom_system_prompt.strip() + "\n\nAvailable Tools:" + tools_part
                except Exception:
                    system_msg = custom_system_prompt
            else:
                system_msg = custom_system_prompt
        else:
            system_msg = LLM_SYSTEM_MSG
        fmt = "json"
    else:
        system_msg = "You are a helpful AI."
        fmt = None
        
    # Inject timestamp to bypass API/proxy caches
    from datetime import datetime
    system_msg += f"\n\n[System Time: {datetime.now().isoformat()}]"

    # Slice history based on settings context size
    sliced_history = []
    if history and ctx_size > 0:
        sliced_history = history[-ctx_size:]

    if source == "cloud":
        # Call OpenAI / Cloud provider
        headers = {
            "Content-Type": "application/json",
        }
        if cloud_api_key:
            headers["Authorization"] = f"Bearer {cloud_api_key}"

        messages_payload = [
            {"role": "system", "content": system_msg}
        ]
        for m in sliced_history:
            role = getattr(m, "role", None) or m.get("role") if isinstance(m, dict) else m.role
            content = getattr(m, "content", None) or m.get("content") if isinstance(m, dict) else m.content
            if role in ("user", "assistant"):
                # Clean HTML tags and buttons from assistant replies for clean context
                if role == "assistant":
                    if any(k in content for k in ["Plan created", "✔", "hx-post", "Plan dibatalkan"]):
                        continue
                    content = _clean_html_for_llm(content)
                    if not content:
                        continue
                messages_payload.append({"role": role, "content": content})
        
        # Append current user prompt
        messages_payload.append({"role": "user", "content": prompt})

        payload = {
            "model": cloud_model,
            "messages": messages_payload,
        }
        
        # Reasoning models (o1, o3, gpt-5-nano) often reject 'temperature' parameter
        if not (cloud_model.startswith("o1") or cloud_model.startswith("o3") or "gpt-5-nano" in cloud_model):
            payload["temperature"] = max(0.0, min(float(temperature), 1.0))

        # We don't force response_format to avoid incompatibilities with LM Studio/LocalAI/vLLM
        # if fmt == "json":
        #     payload["response_format"] = {"type": "json_object"}

        r = requests.post(cloud_endpoint, json=payload, headers=headers, timeout=(5, timeout))
        r.raise_for_status()
        data = r.json()

        # OpenAI format: choices[0].message.content
        resp_text = (data.get("choices") or [{}])[0].get("message", {}).get("content") or ""
        return resp_text
    else:
        # Local Ollama using /api/chat (native messages support!)
        url = f"{_get_ollama_base_url()}/api/chat"

        messages_payload = [
            {"role": "system", "content": system_msg}
        ]
        for m in sliced_history:
            role = getattr(m, "role", None) or m.get("role") if isinstance(m, dict) else m.role
            content = getattr(m, "content", None) or m.get("content") if isinstance(m, dict) else m.content
            if role in ("user", "assistant"):
                # Clean HTML tags and buttons from assistant replies for clean context
                if role == "assistant":
                    if any(k in content for k in ["Plan created", "✔", "hx-post", "Plan dibatalkan"]):
                        continue
                    content = _clean_html_for_llm(content)
                    if not content:
                        continue
                messages_payload.append({"role": role, "content": content})
        
        # Append current user prompt
        messages_payload.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages_payload,
            "stream": False,
            "options": {"temperature": max(0.0, min(float(temperature), 1.0))},
        }
        if fmt == "json":
            payload["format"] = "json"

        r = requests.post(url, json=payload, timeout=(5, timeout))
        r.raise_for_status()
        data = r.json()
        return data.get("message", {}).get("content") or ""


# ============================
# Rule validation / fallback
# ============================
def _validate_and_normalize(rules: Any) -> List[Dict[str, Any]]:
    # dict with "rules" list
    if isinstance(rules, dict) and isinstance(rules.get("rules"), list):
        rules = rules["rules"]

    # single rule dict -> wrap
    if isinstance(rules, dict):
        if "pattern" in rules or {"id", "label", "reason"} & set(rules.keys()):
            rules = [rules]

    out: List[Dict[str, Any]] = []
    if not isinstance(rules, list):
        return out

    seen = set()
    for i, obj in enumerate(rules):
        if not isinstance(obj, dict):
            continue

        rid = str(obj.get("id") or f"custom-{i+1}")
        rid = re.sub(r"[^a-zA-Z0-9_\-\.]", "-", rid).lower()

        label = (obj.get("label") or "INFO").upper()
        if label not in ("HIGH", "MEDIUM", "LOW", "INFO"):
            label = "INFO"

        reason = obj.get("reason") or "-"
        pattern = obj.get("pattern") or ""
        if not isinstance(pattern, str) or not pattern.strip():
            continue

        code_in = obj.get("code_in") or [200, 206]

        try:
            re.compile(pattern)
        except re.error:
            continue

        key = (rid, pattern, label)
        if key in seen:
            continue
        seen.add(key)

        out.append(
            {
                "id": rid,
                "label": label,
                "reason": reason,
                "pattern": pattern,
                "code_in": code_in,
            }
        )
    return out


def _fallback_rules_from_urls(urls: list[str], max_rules: int = 12) -> list[dict]:
    exts = collections.Counter()
    dirs = collections.Counter()
    for u in urls:
        low = u.lower()
        for ext in (
            ".zip",
            ".rar",
            ".7z",
            ".tar",
            ".tgz",
            ".tar.gz",
            ".gz",
            ".bz2",
            ".sql",
            ".sqlite",
            ".db",
            ".dump",
            ".log",
            ".bak",
            ".old",
            ".php",
            ".asp",
            ".aspx",
            ".jsp",
            ".rb",
            ".py",
            ".cgi",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".csv",
            ".pdf",
            ".json",
            ".xml",
        ):
            if ext in low:
                exts[ext] += 1
        for d in (
            "/admin",
            "/administrator",
            "/wp-admin",
            "/dashboard",
            "/uploads",
            "/upload",
            "/filemanager",
            "/userfiles",
            "/backup",
            "/backups",
            "/config",
            "/.env",
            "/phpinfo",
            "/debug",
            "/test",
            "/tmp",
            "/logs",
            "/log",
        ):
            if d in low:
                dirs[d] += 1

    rules: list[dict] = []

    def add_rule(_id, _label, _reason, _pattern, _codes=[200, 206]):
        rules.append(
            {"id": _id, "label": _label, "reason": _reason, "pattern": _pattern, "code_in": _codes}
        )

    if any(e in exts for e in [".zip", ".rar", ".7z", ".tar", ".tgz", ".tar.gz", ".gz", ".bz2"]):
        add_rule(
            "fb-high-archives",
            "HIGH",
            "Backup/source archives exposed",
            r"\.(?:zip|rar|7z|tar|tgz|tar\.gz|gz|bz2)$",
        )
    if any(e in exts for e in [".sql", ".sqlite", ".db", ".dump"]):
        add_rule(
            "fb-high-db",
            "HIGH",
            "Database dumps exposed",
            r"\.(?:sql|sqlite|db|dump)(?:\.(?:gz|bz2|zip))?$",
        )
    if any(d in dirs for d in ["/admin", "/administrator", "/wp-admin", "/dashboard"]):
        add_rule(
            "fb-medium-admin",
            "MEDIUM",
            "Admin panels or dashboards",
            r"/(?:admin|administrator|wp-admin|dashboard)(?:/|$)",
            [200, 302, 401, 403],
        )
    if any(d in dirs for d in ["/uploads", "/upload", "/filemanager", "/userfiles"]):
        add_rule(
            "fb-medium-upload",
            "MEDIUM",
            "Upload or file manager directories",
            r"/(?:uploads?|filemanager|userfiles?)(?:/|$)",
            [200, 403],
        )
    if any(d in dirs for d in ["/config", "/.env"]):
        add_rule(
            "fb-low-config",
            "LOW",
            "Config or environment files",
            r"/(?:\.env|config\.php|settings\.json)$",
            [200, 403],
        )
    if any(d in dirs for d in ["/logs", "/log"]) or ".log" in exts:
        add_rule(
            "fb-low-logs",
            "LOW",
            "Log files exposed",
            r"/(?:access|error)\.log(?:\.\w+)?$",
            [200, 403],
        )
    if any(e in exts for e in [".php", ".asp", ".aspx", ".jsp", ".rb", ".py", ".cgi"]):
        add_rule(
            "fb-info-src",
            "INFO",
            "Source code paths",
            r"\.(?:php|asp|aspx|jsp|rb|py|cgi)$",
            [200, 403],
        )
    if any(e in exts for e in [".doc", ".docx", ".xls", ".xlsx", ".csv", ".pdf", ".json", ".xml"]):
        add_rule(
            "fb-info-docs",
            "INFO",
            "Document/data files",
            r"\.(?:docx?|xlsx?|csv|pdf|json|xml)$",
            [200, 206],
        )
    return rules[:max_rules]


# ============================
# RULE generation main
# ============================
def generate_rules_from_samples(
    outputs_root: Path,
    scope: str,
    sample_size: int = 200,
    model: str = DEFAULT_MODEL,
    timeout: int = DEFAULT_TIMEOUT,
    temperature: float = 0.5,
    retries: int = 0,
) -> Dict[str, Any]:
    urls = load_urls(outputs_root, scope)
    if not urls:
        return {"ok": False, "error": "urls.txt not found or empty"}

    sample = sample_urls(urls, sample_size=sample_size)
    prompt = _build_prompt(sample)

    dbg_dir = _cache_dir(outputs_root, scope) / "ai_debug"
    dbg_dir.mkdir(parents=True, exist_ok=True)
    (dbg_dir / "rulegen_prompt.txt").write_text(prompt, encoding="utf-8")

    attempts = max(1, 1 + int(retries))
    errors = []
    all_rules: list[dict] = []

    for i in range(attempts):
        try:
            use_prompt = prompt
            if i > 0:
                use_prompt = (
                    "The previous output did not follow the required format.\n"
                    "REMINDER: Return a JSON ARRAY of rule objects only (no wrapper keys, no markdown, no text).\n"
                    "Each object must have: id, label (HIGH|MEDIUM|LOW|INFO), reason, pattern, code_in.\n\n"
                ) + prompt

            raw = _call_ollama(
                use_prompt, model=model, timeout=timeout, temperature=temperature, mode="rules"
            )

            raw_path = _debug_path(outputs_root, scope, f"rulegen_raw_{i+1}.json")
            raw_path.write_text(
                json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8"
            )

            rules = _parse_rules(raw)
            if rules:
                all_rules.extend(rules)
                break
        except Exception as e:
            errors.append(str(e))
            continue

    if not all_rules:
        fb = _fallback_rules_from_urls(sample, max_rules=12)
        if fb:
            out_path = _generated_rules_path(outputs_root, scope)
            out_path.write_text(json.dumps(fb, ensure_ascii=False, indent=2), encoding="utf-8")
            return {
                "ok": True,
                "scope": scope,
                "rules_count": len(fb),
                "path": str(out_path),
                "attempts": attempts,
                "fallback": True,
            }
        msg = "no valid rules parsed from model output"
        if errors:
            msg += f" | errors: {errors[:1][0]}"
        return {"ok": False, "error": msg}

    out_path = _generated_rules_path(outputs_root, scope)
    out_path.write_text(json.dumps(all_rules, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "ok": True,
        "scope": scope,
        "rules_count": len(all_rules),
        "path": str(out_path),
        "attempts": attempts,
    }


# ============================
# JSON parsing helpers
# ============================
def _strip_code_fence(s: str) -> str:
    if not isinstance(s, str):
        return s
    s = s.strip()
    if s.startswith("```"):
        s = s.strip("`")
        if s.startswith("json"):
            s = s[4:]
        m = re.search(r"[\{\[]", s)
        if m:
            s = s[m.start():]
    last = max(s.rfind("}"), s.rfind("]"))
    if last != -1:
        s = s[: last + 1]
    return s.strip()


def _json_loads_loose(s: Any) -> Any:
    if isinstance(s, (dict, list)):
        return s
    if not isinstance(s, str):
        return None
    text = _strip_code_fence(s)
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"(\{.*\}|\[.*\])", text, flags=re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                pass
    return None


# ============================
# Rule parsing for generate_rules_from_samples
# ============================
def _parse_rules(raw: Any) -> List[Dict[str, Any]]:
    data = _json_loads_loose(raw)
    if data is None:
        return []
    return _validate_and_normalize(data)


# ============================
# Simple heuristic plan (kept)
# ============================
def parse_prompt_to_plan(
    prompt: str,
    scope: str,
    model: str = DEFAULT_MODEL,
    intent: str = "auto",
) -> Dict[str, Any]:
    text = (prompt or "").lower()
    actions = []
    if any(k in text for k in ["subdomain", "sub domain", "aktif", "alive"]):
        actions.append({"tool": "subdomains_alive", "args": {}})
    if not actions and any(k in text for k in ["analisa", "analyze", "ringkas", "summary"]):
        actions.append({"tool": "analyze", "args": {}})
    if not actions:
        actions.append({"tool": "analyze", "args": {}})

    return {
        "intent": intent or "auto",
        "prompt": prompt,
        "scope": scope,
        "model": model,
        "actions": actions,
    }


# ============================
# LLM-driven router (STRICT JSON chat/plan/confirm/revise)
# ============================
def _get_llama_api() -> str:
    return f"{_get_ollama_base_url()}/api/generate"

LLM_SYSTEM_MSG = (
    "You are a professional security pentest copilot inside ReconLens.\n"
    "Based on the user prompt, decide among these 4 intents and return STRICT JSON ONLY:\n"
    "1) {\"type\":\"chat\",\"reply\":\"...\"}\n"
    "   For greetings, small-talk, or questions about capabilities.\n"
    "2) {\"type\":\"actions\",\"summary\":\"...\",\"actions\":[{\"tool\":\"...\",\"args\":{}}],\"needs_confirmation\":false}\n"
    "   For safe actions or when the user explicitly confirms to run an action.\n"
    "3) {\"type\":\"confirm\",\"summary\":\"...\",\"actions\":[{\"tool\":\"...\",\"args\":{}}],\"needs_confirmation\":true}\n"
    "   For active recon/scanning tasks that require user approval.\n"
    "4) {\"type\":\"revise\",\"question\":\"...\"}\n"
    "   If the request is highly ambiguous.\n\n"
    "Available Tools:\n"
    "- 'bash': Use to execute ANY arbitrary Bash/shell command on the target folder (e.g. using grep, wc -l, ping, python scripts, cat, sort, awk, sed, etc.) to perform customized tasks, connectivity checks (ping), script execution, or deep command-line analysis, search, or triage on files like urls.txt, subdomains.txt, etc. (args: {'command': '<shell command>'}).\n"
    "- 'subdomains_alive': Use to list/filter active or alive subdomains (args: {'target': '<scope>'}).\n"
    "- 'subfinder': Runs passive subdomain discovery (args: {'target': '<scope>'}).\n"
    "- 'dirsearch': Runs active directory bruteforcing (args: {'target': '<scope>'}).\n"
    "- 'gau': Runs passive URL discovery via GAU (args: {'target': '<scope>'}).\n"
    "- 'waymore': Runs deep passive Wayback URL discovery (args: {'target': '<scope>'}).\n"
    "- 'urlfinder': Runs active JS/HTML crawler for URL extraction (args: {'target': '<scope>'}).\n\n"
    "CRITICAL RULE:\n"
    "1) If the user asks to analyze, count, or summarize ALREADY found URLs/findings, you MUST use the 'bash' tool with 'type':'actions'. Write a bash command (like grep, awk, wc -l) to extract the requested information. Do NOT use recon tools (gau, waymore, urlfinder, subfinder) unless the user explicitly wants to find NEW data.\n"
    "2) You are running as ROOT inside a Linux Docker container. If the user asks about the OS, environment, or requests package installations (like ping, nmap, etc.), you MUST use the 'bash' tool (e.g. uname -a, cat /etc/os-release, apt-get update && apt-get install -y <pkg>) with 'type':'actions' instead of replying directly.\n"
    "3) If you are generating/writing a custom Python, Bash, or any other executable script, you MUST save it inside a 'scripts/' subdirectory to keep the workspace clean (e.g., 'mkdir -p scripts && echo \"...\" > scripts/myscript.py').\n"
    "4) If the user asks you to save the output of a command or script, or if the script produces a large dataset that needs to be stored, ALWAYS redirect the output to a file inside the 'raw/' subdirectory (e.g., 'python3 scripts/myscript.py > raw/myscript_output.txt').\n"
    "5) If the user asks you to analyze the result of a recent scan, tool (e.g., nmap), background job, or custom bash command, DO NOT ask the user for the file name. You MUST proactively use the 'bash' tool (with 'type':'actions') to search the 'raw/' directory (e.g., `ls -lth raw/` or `cat raw/custom_bash-*`) to find the latest output files and read them.\n\n"
    "Keep answers in user's language. STRICT JSON ONLY."
)

_JSON_BLOCK_RE = re.compile(r"(\{(?:.|\n)*\}|\[(?:.|\n)*\])", re.MULTILINE)


def _extract_first_json_block(s: str):
    s = (s or "").strip()
    try:
        return json.loads(s)
    except Exception:
        m = _JSON_BLOCK_RE.search(s)
        if not m:
            raise ValueError("No JSON block found")
        cand = m.group(1)
        for end in range(len(cand), 0, -1):
            try:
                return json.loads(cand[:end])
            except Exception:
                pass
        raise ValueError("Failed to parse JSON block")


def _ollama_json_router(prompt: str, model: str = DEFAULT_MODEL, temperature: float = 0.0, timeout: int = DEFAULT_TIMEOUT) -> dict:
    payload = {
        "model": model,
        "prompt": prompt,
        "system": LLM_SYSTEM_MSG,
        "stream": False,
        "format": "json",
        "options": {"temperature": float(temperature)},
    }
    r = requests.post(_get_llama_api(), json=payload, timeout=(5, timeout))
    r.raise_for_status()
    data = r.json()
    resp = data.get("response") or data.get("text") or data.get("output") or ""
    if isinstance(resp, (dict, list)):
        parsed = resp
    else:
        parsed = _extract_first_json_block(str(resp))
    if not isinstance(parsed, dict):
        return {"type": "chat", "reply": json.dumps(parsed, ensure_ascii=False)}
    return parsed


def _normalize_actions(scope: str, actions: list[dict]) -> list[dict]:
    out = []
    for a in (actions or []):
        name = (a.get("tool") or a.get("name") or "").strip().lower()
        args = dict(a.get("args") or {})

        # alias → internal
        if name in ("subdomain", "subdomains", "list_active_subdomains", "subdomains_alive"):
            name = "subdomains_alive"

        elif name in ("dirsearch", "dirbuster", "dir"):
            name = "dirsearch"
            args.setdefault("target", scope)

        elif name in ("analyze", "insight", "summary"):
            name = "analyze"

        out.append({"tool": name, "args": args})
    return out


def plan_or_chat_via_llm(
    *,
    prompt: str,
    scope: str,
    model: str = DEFAULT_MODEL,
    intent: str = "auto"
) -> Dict[str, Any]:
    """
    Keluaran salah satu:
      - {"type":"chat","reply":"..."}
      - {"type":"confirm","summary":"...","actions":[...],"needs_confirmation":true}
      - {"type":"actions","summary":"...","actions":[...],"needs_confirmation":false}
      - {"type":"revise","question":"..."}
    """
    parsed = _ollama_json_router(prompt, model=model)
    t = str(parsed.get("type") or "").lower()

    if t in ("actions", "confirm"):
        parsed["actions"] = _normalize_actions(scope, parsed.get("actions", []))
        if t == "actions" and "needs_confirmation" not in parsed:
            parsed["needs_confirmation"] = False
        if t == "confirm":
            parsed["needs_confirmation"] = True
        return parsed

    if t == "revise":
        return {"type": "revise", "question": parsed.get("question") or "Bisa perjelas maksudnya?"}

    reply = parsed.get("reply") or parsed.get("message") or json.dumps(parsed, ensure_ascii=False)
    return {"type": "chat", "reply": reply}


# ============================
# Legacy hybrid (heuristik + LLM fallback)
# ============================
def _parse_prompt_to_plan_or_chat_inner(
    *,
    prompt: str,
    scope: str,
    model: str = DEFAULT_MODEL,
    intent: str = "auto",
    timeout: int = DEFAULT_TIMEOUT,
    err_container: list = None,
    history: list = None,
    append_msg_cb = None
) -> Dict[str, Any]:
    """
    Return salah satu:
      - {"type":"chat","reply":"..."}
      - {"type":"confirm","summary":"...","actions":[...],"needs_confirmation":true}
      - {"type":"actions","summary":"...","actions":[...],"needs_confirmation":false}
      - {"type":"revise","question":"..."}
    Fallback: heuristik → chat/plan sederhana.
    """
    p = (prompt or "").strip()
    lower = p.lower()

    # removed heuristic bypasses to rely on agentic loop

    # Coba LLM mode "command"
    resp = None
    import subprocess

    class _LoopMsg:
        def __init__(self, role, content):
            self.role = role
            self.content = content

    current_history = list(history) if history else []
    
    # Inject recent raw files to give AI context about newly completed background jobs
    recent_files = ""
    raw_dir = Path(f"outputs/{scope}/raw")
    if raw_dir.exists():
        try:
            files = sorted(raw_dir.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True)[:5]
            if files:
                recent_files = "\n\n[System Hint] If the user asks to analyze recent outputs or scans, the latest files are:\n" + "\n".join([f"- raw/{f.name}" for f in files]) + "\n(Do NOT delete these files unless explicitly asked to delete files)."
        except Exception:
            pass

    loop_prompt = f"[scope:{scope}][intent:{intent}] {p}{recent_files}"
    
    for turn in range(3):
        try:
            resp = _call_ollama(
                prompt=loop_prompt,
                model=model,
                timeout=timeout,
                temperature=0.3,
                mode="command",
                history=current_history,
            )
            print(f"[debug-llm] turn {turn} raw response: {resp}", flush=True)
            data = _json_loads_loose(resp)
            if not isinstance(data, dict):
                raise ValueError("LLM response did not contain a valid JSON object.")
            if "type" not in data:
                # If no strict type but looks like a chat response, assign chat type
                if "reply" in data or "summary" in data or "message" in data:
                    data["type"] = "chat"
                else:
                    raise ValueError("LLM response did not contain a valid JSON object with a 'type' key.")
        
            t = str(data.get("type") or "").lower()
            if t in ("chat", "actions", "confirm", "revise"):
                    acts = data.get("actions")
                    if acts is not None and not isinstance(acts, list):
                        acts = [acts]
                        data["actions"] = acts
                    if isinstance(acts, list):
                        for a in acts:
                            if "args" not in a or a["args"] is None:
                                a["args"] = {}
                    if isinstance(acts, list):
                        for a in acts:
                            a["args"].setdefault("target", scope)
                
                    # Check for agentic background bash tool
                    is_all_bash = acts and all(a.get("tool", "").lower() == "bash" for a in acts)
                    
                    if t == "confirm" and is_all_bash:
                        import base64
                        combined_cmd = " && ".join(filter(None, [a.get("args", {}).get("command") for a in acts]))
                        encoded_cmd = base64.b64encode(combined_cmd.encode('utf-8')).decode('utf-8')
                        data["meta"] = {
                            "kind": "proposal_bash",
                            "tool": "custom_bash",
                            "tool_upper": "BASH",
                            "tool_name": "Custom Bash Shell",
                            "query_params": f"?cmd_b64={encoded_cmd}",
                            "raw_cmd": combined_cmd
                        }
                        reply = data.get("summary") or data.get("reply") or "Anda ingin menjalankan perintah Bash custom. Silakan tinjau dan jalankan di konsol."
                        return {"type": "chat", "reply": reply, "meta": data.get("meta")}

                    if t == "actions" and is_all_bash:
                        combined_output = ""
                        has_executed = False
                        
                        for a in acts:
                            cmd = a.get("args", {}).get("command")
                            if not cmd:
                                continue
                            
                            has_executed = True
                            try:
                                cwd = f"outputs/{scope}"
                                if not os.path.exists(cwd):
                                    os.makedirs(cwd, exist_ok=True)
                            
                                # Limit output to avoid context window explosion
                                run_res = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=15)
                                out_text = run_res.stdout.strip()
                                if run_res.stderr:
                                    out_text += "\n" + run_res.stderr.strip()
                                if not out_text:
                                    out_text = "(Command executed successfully, no output)"
                                if len(out_text) > 2000:
                                    out_text = out_text[:2000] + "\n... (output truncated)"
                            except Exception as e:
                                out_text = f"Error executing bash command: {e}"
                                
                            combined_output += f"\n$ {cmd}\n{out_text}\n"
                            
                            if append_msg_cb:
                                esc_cmd = cmd.replace('<', '&lt;').replace('>', '&gt;')
                                esc_out = out_text.replace('<', '&lt;').replace('>', '&gt;')
                                html_block = f"""
<details class="mb-2 bg-slate-900 rounded-lg overflow-hidden border border-slate-700 shadow-sm text-left group">
  <summary class="px-3 py-2 text-[10px] uppercase font-bold text-slate-400 cursor-pointer hover:bg-slate-800 flex items-center gap-2 transition-colors">
    <span class="text-emerald-400 group-open:text-emerald-300">⚡ System Tool</span>
    <span class="text-slate-500 lowercase normal-case truncate max-w-[200px] group-open:hidden">{esc_cmd[:40]}...</span>
    <span class="ml-auto text-[10px] text-slate-600 group-open:rotate-180 transition-transform">▼</span>
  </summary>
  <div class="p-3 text-[11px] font-mono text-slate-300 overflow-x-auto border-t border-slate-700 max-h-[300px] overflow-y-auto bg-black">
    <div class="text-indigo-400 mb-2 whitespace-pre-wrap">$ {esc_cmd}</div>
    <div class="text-slate-400 whitespace-pre-wrap">{esc_out}</div>
  </div>
</details>
"""
                                append_msg_cb("assistant", html_block, {"html": True})

                        if has_executed:
                            current_history.append(_LoopMsg("assistant", json.dumps(data)))
                            current_history.append(_LoopMsg("user", f"Bash commands executed. Outputs:\n{combined_output}"))
                            loop_prompt = "Based on the command output above, please provide the final answer to my original question. REMEMBER: You MUST output STRICT JSON using one of the intent types (e.g. {\"type\": \"chat\", \"reply\": \"...\"})."
                            continue
                
                    # Pasang metadata proposal card jika LLM memicu CLI tool
                    for a in (acts or []):
                        tool = str(a.get("tool") or "").lower()
                        if tool in ("gau", "waymore", "urlfinder", "dirsearch", "subfinder", "subdomains_alive"):
                            target_host = a.get("args", {}).get("host") or a.get("args", {}).get("target") or scope
                            query_params = f"?host={target_host}" if tool == "dirsearch" else ""
                            tool_map = {
                                "gau": ("GAU", "GAU (GetAllUrls)"),
                                "waymore": ("WAYMORE", "Waymore"),
                                "urlfinder": ("URLFINDER", "URLFinder"),
                                "dirsearch": ("DIRSEARCH", "Dirsearch"),
                                "subfinder": ("SUBFINDER", "Subfinder"),
                                "subdomains_alive": ("SUBFINDER", "Subfinder")
                            }
                            tool_info = tool_map.get(tool, (tool.upper(), tool.capitalize()))
                            data["meta"] = {
                                "kind": "proposal",
                                "tool": "subfinder" if tool == "subdomains_alive" else tool,
                                "tool_upper": tool_info[0],
                                "tool_name": tool_info[1],
                                "query_params": query_params,
                                "target_host": target_host
                            }
                            break

                    if t in ("actions", "confirm"):
                        if not acts:
                            reply = data.get("summary") or data.get("reply") or "Saya siap membantu melakukan analisis pasif maupun aktif. Silakan pilih tool pemindaian yang ingin dijalankan!"
                            return {"type": "chat", "reply": reply, "meta": data.get("meta")}

                        # Detect if any tool in acts is a background CLI tool
                        is_cli = False
                        cli_tool_name = "Recon tool"
                        for a in acts:
                            tool = str(a.get("tool") or "").lower()
                            if tool in ("gau", "waymore", "urlfinder", "dirsearch", "subfinder"):
                                is_cli = True
                                cli_tool_name = tool.upper()
                                break

                        if is_cli:
                            reply = data.get("summary") or data.get("reply") or f"Saya mendeteksi Anda ingin menjalankan pemindaian menggunakan **{cli_tool_name}**. Silakan klik tombol di bawah ini untuk meluncurkannya di CLI Runner Console!"
                            return {
                                "type": "chat",
                                "reply": reply,
                                "meta": data.get("meta")
                            }

                        return {
                            "type": "actions",
                            "plan": {
                                "summary": data.get("summary") or data.get("reply") or "Rencana aksi otomatis.",
                                "actions": acts
                            },
                            "meta": data.get("meta")
                        }

                    return data
            else:
                # If t is not in known intents, treat as chat
                reply_text = data.get("reply") or data.get("message") or data.get("text") or json.dumps(data)
                return {
                    "type": "chat",
                    "reply": reply_text,
                    "meta": data.get("meta")
                }
        except Exception as e:
            if "Connection refused" in str(e) or "Max retries exceeded" in str(e):
                return {
                    "type": "chat",
                    "reply": "⚠️ Maaf Bro, sepertinya ada gangguan jaringan saat mencoba terhubung ke API AI (Connection Refused). Mungkin koneksi internet sedang putus-nyambung atau diblokir oleh sistem/firewall Anda. Silakan coba lagi sebentar lagi!"
                }
            if err_container is not None:
                err_msg = f"{type(e).__name__}: {str(e)}"
                if hasattr(e, "response") and e.response is not None:
                    try:
                        err_msg += f" - Response: {e.response.text}"
                    except:
                        pass
                err_container.append(err_msg)
            print(f"[rulegen] Fallback: {e}")
            # Jika LLM berhasil merespon tetapi bukan JSON valid (misal, kode python/prosa mentah),
            # langsung kembalikan respon chat tersebut agar tidak hilang dibuang ke default fallback.
            if resp and len(resp.strip()) > 5:
                if err_container is not None:
                    err_container.clear() # Clear error so it doesn't get tagged as Heuristic Fallback
                return {"type": "chat", "reply": resp}
            break

    return {"type": "chat", "reply": "Maaf bro, saya kesulitan memproses instruksi ini. Coba sampaikan dengan lebih spesifik."}


def parse_prompt_to_plan_or_chat(
    *,
    prompt: str,
    scope: str,
    model: str = DEFAULT_MODEL,
    intent: str = "auto",
    timeout: int = DEFAULT_TIMEOUT,
    history: list = None,
    append_msg_cb = None
) -> Dict[str, Any]:
    from app.core.config_store import load_settings

    # Determine the model name dynamically
    try:
        settings = load_settings()
        ai_cfg = settings.get("ai", {})
        source = ai_cfg.get("source") or "local"
        if source == "cloud":
            ep = ai_cfg.get("endpoint") or ""
            model_val = ai_cfg.get("model") or "gpt-3.5-turbo"
            if "localhost" in ep or "127.0.0.1" in ep:
                model_desc = f"{model_val} (LM Studio)"
            else:
                model_desc = f"{model_val} (Cloud)"
        else:
            model_desc = f"{model} (Ollama)"
    except Exception:
        model_desc = f"{model} (Ollama)"

    err_container = []

    # Call the inner function
    res = _parse_prompt_to_plan_or_chat_inner(
        prompt=prompt,
        scope=scope,
        model=model,
        intent=intent,
        timeout=timeout,
        err_container=err_container,
        history=history,
        append_msg_cb=append_msg_cb
    )

    # Add model info to result
    if res and isinstance(res, dict):
        res.setdefault("meta", {})
        if not isinstance(res["meta"], dict):
            res["meta"] = {}

        if err_container:
            res["meta"]["model_name"] = f"Heuristic Fallback ({err_container[0]})"
        elif "Heuristic fallback" in str(res.get("summary", "")) or "darurat" in str(res.get("reply", "")):
            res["meta"]["model_name"] = "Heuristic Fallback"
        else:
            res["meta"]["model_name"] = model_desc

    return res

