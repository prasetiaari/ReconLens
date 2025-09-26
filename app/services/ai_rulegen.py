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

DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_TIMEOUT = 60  # detik

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


# ============================
# Ollama call (multi-mode)
# ============================
def _call_ollama(
    prompt: str,
    model: str,
    timeout: int,
    temperature: float = 0.5,
    mode: str = "rules",  # "rules" | "command"
) -> Any:
    """
    mode="rules"   : strict JSON array of rule objects
    mode="command" : strict JSON for chat/plan/confirm/revise
    """
    url = "http://localhost:11434/api/generate"

    if mode == "rules":
        system_msg = (
            "You are a strict JSON generator. "
            "Always return a JSON array of rule objects, and nothing else. "
            "Never include wrapper keys like 'results', 'data', or 'summary'. "
            "No markdown, no explanations."
        )
        fmt = "json"
    elif mode == "command":
        system_msg = (
            "You are an AI assistant inside ReconLens.\n"
            "Decide among four intents and ALWAYS return STRICT JSON (no markdown, no prose):\n"
            "1) {\"type\":\"chat\",\"reply\":\"...\"}\n"
            "   Use when user small-talks or asks general questions (date/time, greetings, etc.).\n"
            "2) {\"type\":\"actions\",\"summary\":\"...\",\"actions\":[{\"tool\":\"...\",\"args\":{}}],\"needs_confirmation\":false}\n"
            "   Use when user explicitly confirms to run or the action is clearly safe auto-run.\n"
            "3) {\"type\":\"confirm\",\"summary\":\"...\",\"actions\":[{\"tool\":\"...\",\"args\":{}}],\"needs_confirmation\":true}\n"
            "   Use when user asks to run a tool (e.g., subdomain, dirsearch, scan) but confirmation is required.\n"
            "4) {\"type\":\"revise\",\"question\":\"...\"}\n"
            "   Use if the request is ambiguous and needs clarification.\n"
            "Keep answers in user's language. STRICT JSON ONLY."
        )
        fmt = "json"
    else:
        system_msg = "You are a helpful AI."
        fmt = None

    payload = {
        "model": model,
        "prompt": prompt,
        "system": system_msg,
        "stream": False,
        "format": fmt,  # let Ollama emit pure JSON
        "options": {"temperature": max(0.0, min(float(temperature), 1.0))},
    }
    r = requests.post(url, json=payload, timeout=(5, timeout))
    r.raise_for_status()
    data = r.json()
    return data.get("response")


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
_LLAMA_API = "http://localhost:11434/api/generate"

LLM_SYSTEM_MSG = (
    "You are an AI assistant inside ReconLens.\n"
    "Decide among four intents and ALWAYS return STRICT JSON (no markdown, no prose):\n"
    "1) {\"type\":\"chat\",\"reply\":\"...\"}\n"
    "   Use when user small-talks or asks general questions (date/time, greetings, etc.).\n"
    "2) {\"type\":\"actions\",\"summary\":\"...\",\"actions\":[{\"tool\":\"...\",\"args\":{}}],\"needs_confirmation\":false}\n"
    "   Use when user explicitly confirms to run or the action is clearly safe auto-run.\n"
    "3) {\"type\":\"confirm\",\"summary\":\"...\",\"actions\":[{\"tool\":\"...\",\"args\":{}}],\"needs_confirmation\":true}\n"
    "   Use when user asks to run a tool (e.g., subdomain, dirsearch, scan) but confirmation is required.\n"
    "4) {\"type\":\"revise\",\"question\":\"...\"}\n"
    "   Use if the request is ambiguous and needs clarification.\n"
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
    r = requests.post(_LLAMA_API, json=payload, timeout=(5, timeout))
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
def parse_prompt_to_plan_or_chat(
    *,
    prompt: str,
    scope: str,
    model: str = DEFAULT_MODEL,
    intent: str = "auto",
    timeout: int = DEFAULT_TIMEOUT
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
    # Heuristik cepat: greetings & small-talk → langsung chat
    smalltalk = ("halo", "hai", "hello", "hei", "thanks", "terima kasih", "apa kabar")
    if any(tok in p.lower() for tok in smalltalk):
        return {"type": "chat", "reply": f"Halo! Siap bantu di scope {scope}. Mau analisa apa?"}

    # Coba LLM mode "command"
    try:
        resp = _call_ollama(
            prompt=f"[scope:{scope}][intent:{intent}] {p}",
            model=model,
            timeout=timeout,
            temperature=0.3,
            mode="command",
        )
        data = _json_loads_loose(resp)
        if isinstance(data, dict) and "type" in data:
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
                return data
    except Exception:
        pass

    # Fallback logika ringan
    lower = p.lower()
    if "subdomain" in lower and ("aktif" in lower or "alive" in lower or "200" in lower):
        return {
            "type": "confirm",
            "summary": "Menampilkan seluruh subdomain aktif.",
            "actions": [{"tool": "subdomains_alive", "args": {"target": scope}}],
            "needs_confirmation": True,
        }
    if any(k in lower for k in ["insight", "ringkas", "summary", "analisa", "analyze"]):
        return {
            "type": "confirm",
            "summary": "Analisa temuan saat ini.",
            "actions": [{"tool": "analyze", "args": {"target": scope, "query": p}}],
            "needs_confirmation": True,
        }
    return {"type": "chat", "reply": "Catat. Bisa jalankan tools kalau perlu. Mau aku buat rencana aksi dulu?"}
