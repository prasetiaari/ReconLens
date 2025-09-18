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


DEFAULT_MODEL = "llama3.2:3b"   # lebih ringan untuk cepat generate rules
DEFAULT_TIMEOUT = 60            # detik


def _outputs_scope_dir(outputs_root: Path, scope: str) -> Path:
    return outputs_root / scope


def _cache_dir(outputs_root: Path, scope: str) -> Path:
    d = _outputs_scope_dir(outputs_root, scope) / "__cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _urls_path(outputs_root: Path, scope: str) -> Path:
    return _outputs_scope_dir(outputs_root, scope) / "urls.txt"


def _generated_rules_path(outputs_root: Path, scope: str) -> Path:
    return _cache_dir(outputs_root, scope) / "ai_rules.generated.json"


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
    # sampling acak tapi stabil-ish: bias ke suffix/path yang variatif
    random.seed(42)
    return random.sample(urls, sample_size)


def _build_prompt(urls: List[str]) -> str:
    examples = [
        {
            "id": "custom-high-archives",
            "label": "HIGH",
            "reason": "Backup/source archives exposed",
            "pattern": r"\.(?:zip|rar|7z|tar|tgz|tar\.gz|gz|bz2)$",
            "code_in": [200, 206]
        },
        {
            "id": "custom-high-db-dumps",
            "label": "HIGH",
            "reason": "Database dumps exposed",
            "pattern": r"\.(?:sql|sqlite|db|dump)(?:\.(?:gz|bz2|zip))?$",
            "code_in": [200, 206]
        },
        {
            "id": "custom-medium-admin",
            "label": "MEDIUM",
            "reason": "Admin panels or dashboards",
            "pattern": r"/(?:admin|administrator|wp-admin|dashboard)(?:/|$)",
            "code_in": [200, 302, 401, 403]
        },
        {
            "id": "custom-medium-upload",
            "label": "MEDIUM",
            "reason": "Upload or file manager directories",
            "pattern": r"/(?:uploads?|filemanager|userfiles?)(?:/|$)",
            "code_in": [200, 403]
        },
        {
            "id": "custom-low-config",
            "label": "LOW",
            "reason": "Config or environment files",
            "pattern": r"/(?:\.env|config\.php|settings\.json)$",
            "code_in": [200, 403]
        }
    ]

    urls_block = "\n".join(urls[:300])  # batasi biar prompt gak kepanjangan

    return (
        "You are a security assistant. Your task: generate concise REGEX rules to detect risky HTTP paths "
        "from the given URLs.\n\n"
        "⚠️ Requirements:\n"
        "- Provide BETWEEN 8 and 15 rules (not less).\n"
        "- Each rule must target a DIFFERENT risk category (e.g., archives, db dumps, admin panels, uploads, configs, logs, source code, etc).\n"
        "- Output MUST be a VALID JSON ARRAY only (no text, no markdown, no explanations).\n"
        "- Each object must have: id, label (HIGH/MEDIUM/LOW/INFO), reason, pattern, code_in.\n"
        #"- Do NOT include keys other than: id, label, reason, pattern, code_in\n"
        "- Use Python-style regex; escape dots; use non-capturing groups (?: ).\n"
        "- Avoid duplicates or overly broad patterns (e.g., just '.*').\n\n"
        "Here are some examples of valid rules:\n"
        f"{json.dumps(examples, ensure_ascii=False, indent=2)}\n\n"
        "=== URL SAMPLES (for inspiration) ===\n"
        f"{urls_block}\n\n"
        "=== OUTPUT JSON ARRAY STARTS BELOW ==="
    )


def _call_ollama(prompt: str, model: str, timeout: int, temperature: float = 0.5) -> Any:
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "system": (
            "You are a strict JSON generator. "
            "Always return a JSON **array** of rule objects, and nothing else. "
            "Never include wrapper keys like 'results', 'data', or 'summary'. "
            "No markdown, no explanations."
        ),
        "stream": False,
        "format": "json",
        "options": {"temperature": max(0.0, min(float(temperature), 1.0))},
    }
    r = requests.post(url, json=payload, timeout=(5, timeout))
    r.raise_for_status()
    data = r.json()
    resp = data.get("response")
    # ... (bagian parsing string → json tetap seperti yang sudah kamu punya)
    return resp


def _validate_and_normalize(rules: Any) -> List[Dict[str, Any]]:
    """
    Terima:
    - list of rule dicts
    - {"rules": [...]}
    - single rule dict -> dibungkus jadi list
    """
    # 1) Kalau dict dengan key "rules" berisi list
    if isinstance(rules, dict) and isinstance(rules.get("rules"), list):
        rules = rules["rules"]

    # 2) Kalau dict tunggal yang terlihat seperti rule → bungkus ke list
    if isinstance(rules, dict):
        # heuristik minimal: ada "pattern" → kemungkinan besar ini 1 rule
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

        # validasi regex
        try:
            re.compile(pattern)
        except re.error:
            continue

        key = (rid, pattern, label)
        if key in seen:
            continue
        seen.add(key)

        out.append({
            "id": rid,
            "label": label,
            "reason": reason,
            "pattern": pattern,
            "code_in": code_in
        })

    return out

def _fallback_rules_from_urls(urls: list[str], max_rules: int = 12) -> list[dict]:
    exts = collections.Counter()
    dirs = collections.Counter()
    for u in urls:
        low = u.lower()
        # hitung ekstensi umum
        for ext in (".zip",".rar",".7z",".tar",".tgz",".tar.gz",".gz",".bz2",
                    ".sql",".sqlite",".db",".dump",".log",".bak",".old",
                    ".php",".asp",".aspx",".jsp",".rb",".py",".cgi",
                    ".doc",".docx",".xls",".xlsx",".csv",".pdf",".json",".xml"):
            if ext in low:
                exts[ext] += 1
        # hitung direktori umum
        for d in ("/admin","/administrator","/wp-admin","/dashboard","/uploads","/upload",
                  "/filemanager","/userfiles","/backup","/backups","/config","/.env",
                  "/phpinfo","/debug","/test","/tmp","/logs","/log"):
            if d in low:
                dirs[d] += 1

    rules: list[dict] = []

    def add_rule(_id,_label,_reason,_pattern,_codes=[200,206]):
        rules.append({"id":_id,"label":_label,"reason":_reason,"pattern":_pattern,"code_in":_codes})

    # archives
    if any(e in exts for e in [".zip",".rar",".7z",".tar",".tgz",".tar.gz",".gz",".bz2"]):
        add_rule("fb-high-archives","HIGH","Backup/source archives exposed", r"\.(?:zip|rar|7z|tar|tgz|tar\.gz|gz|bz2)$")

    # db
    if any(e in exts for e in [".sql",".sqlite",".db",".dump"]):
        add_rule("fb-high-db","HIGH","Database dumps exposed", r"\.(?:sql|sqlite|db|dump)(?:\.(?:gz|bz2|zip))?$")

    # admin
    if any(d in dirs for d in ["/admin","/administrator","/wp-admin","/dashboard"]):
        add_rule("fb-medium-admin","MEDIUM","Admin panels or dashboards", r"/(?:admin|administrator|wp-admin|dashboard)(?:/|$)", [200,302,401,403])

    # uploads
    if any(d in dirs for d in ["/uploads","/upload","/filemanager","/userfiles"]):
        add_rule("fb-medium-upload","MEDIUM","Upload or file manager directories", r"/(?:uploads?|filemanager|userfiles?)(?:/|$)", [200,403])

    # configs
    if any(d in dirs for d in ["/config","/.env"]):
        add_rule("fb-low-config","LOW","Config or environment files", r"/(?:\.env|config\.php|settings\.json)$", [200,403])

    # logs
    if any(d in dirs for d in ["/logs","/log"]) or ".log" in exts:
        add_rule("fb-low-logs","LOW","Log files exposed", r"/(?:access|error)\.log(?:\.\w+)?$", [200,403])

    # source code
    if any(e in exts for e in [".php",".asp",".aspx",".jsp",".rb",".py",".cgi"]):
        add_rule("fb-info-src","INFO","Source code paths", r"\.(?:php|asp|aspx|jsp|rb|py|cgi)$", [200,403])

    # docs
    if any(e in exts for e in [".doc",".docx",".xls",".xlsx",".csv",".pdf",".json",".xml"]):
        add_rule("fb-info-docs","INFO","Document/data files", r"\.(?:docx?|xlsx?|csv|pdf|json|xml)$", [200,206])

    # cap jumlah rule
    return rules[:max_rules]
    
def generate_rules_from_samples(
    outputs_root: Path,
    scope: str,
    sample_size: int = 200,
    model: str = DEFAULT_MODEL,
    timeout: int = DEFAULT_TIMEOUT,
    temperature: float = 0.5,       # NEW
    retries: int = 0,               # NEW: berapa kali coba ekstra jika hasil minim
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
                use_prompt,
                model=model,
                timeout=timeout,
                temperature=temperature,
            )

            # simpan ke debug
            raw_path = _debug_path(outputs_root, scope, f"rulegen_raw_{i+1}.json")
            raw_path.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")

            # validasi & kumpulin rules
            rules = _parse_rules(raw)
            if rules:
                all_rules.extend(rules)
                break  # sukses, keluar loop

        except Exception as e:
            errors.append(str(e))
            continue  # coba lagi kalau masih ada attempt


    if not all_rules:
        # Fallback heuristik biar nggak kosong
        fb = _fallback_rules_from_urls(sample, max_rules=12)
        if fb:
            out_path = _generated_rules_path(outputs_root, scope)
            out_path.write_text(json.dumps(fb, ensure_ascii=False, indent=2), encoding="utf-8")
            return {"ok": True, "scope": scope, "rules_count": len(fb), "path": str(out_path), "attempts": attempts, "fallback": True}
        msg = "no valid rules parsed from model output"
        if errors: msg += f" | errors: {errors[:1][0]}"
        return {"ok": False, "error": msg}
        
        
    '''if not all_rules:
        msg = "no valid rules parsed from model output"
        if errors:
            msg += f" | errors: {errors[:1][0]}"
        return {"ok": False, "error": msg}'''

    # tulis final
    out_path = _generated_rules_path(outputs_root, scope)
    out_path.write_text(json.dumps(all_rules, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "ok": True,
        "scope": scope,
        "rules_count": len(all_rules),
        "path": str(out_path),
        "attempts": attempts,
    }
