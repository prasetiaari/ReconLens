# app/services/ai_analyzer.py
from __future__ import annotations
import os, json, random
from pathlib import Path
from typing import Dict, List, Tuple
from .ai_client import AIClient

SUSPICIOUS_HINTS = ("/admin","/login","/debug","/config",".git",".env",".sql",".zip",".bak")

def _load_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except Exception:
        return {}

def _save_json_atomic(p: Path, data: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)

def _score(url: str) -> int:
    s = url.lower()
    return sum(h in s for h in SUSPICIOUS_HINTS)

def sample_urls(url_map: Dict[str, dict], max_items: int = 40) -> List[Tuple[str, dict]]:
    items = list(url_map.items())
    items.sort(key=lambda kv: _score(kv[0]), reverse=True)
    if len(items) > max_items:
        head, tail = items[:60], items[60:]
        random.shuffle(tail)
        return head + tail[:60]
    return items

PROMPT = """
You are a security assistant.

Classify each URL with one of: HIGH, MEDIUM, LOW, INFO.
Criteria:
- HIGH: sensitive exposure (/.git, /.env, /config.php, /backup.zip, /admin/, /debug/, id_rsa).
- MEDIUM: likely attack surface (/uploads/, /test/, /staging/, /api/).
- LOW: normal but may reveal info (/news/, /docs/).
- INFO: static or irrelevant (/images/, /css/).

STRICT OUTPUT:
Return ONLY a JSON array. No text outside JSON.
Each item: {"url":"...","label":"HIGH|MEDIUM|LOW|INFO","reason":"<=12 words"}.

DATA (one per line):
{block}
""".strip()

def _build_block(pairs: List[Tuple[str, dict]]) -> str:
    return "\n".join(f"- {url}" for url, _ in pairs)
    lines = []
    for url, rec in pairs:
        code = rec.get("code")
        ctype = rec.get("content_type")
        size = rec.get("size")
        lines.append(f"- url={url} code={code} ctype={ctype} size={size}")
    return "\n".join(lines)

def run_ai_classification(outputs_root: Path, scope: str, model_hint: str | None = None) -> dict:
    cache = outputs_root / scope / "__cache"
    debug_dir = cache / "ai_debug"
    debug_dir.mkdir(parents=True, exist_ok=True)

    # catat lingkungan dulu
    (debug_dir / "env.txt").write_text(
        f"outputs_root={outputs_root}\nscope={scope}\ncache={cache}\n", encoding="utf-8"
    )

    url_enrich_path = cache / "url_enrich.json"
    url_map = _load_json(url_enrich_path)

    # Fallback: kalau url_enrich kosong, coba pakai urls.txt → bikin peta minimal
    if not url_map:
        urls_txt = outputs_root / scope / "urls.txt"
        (debug_dir / "note.txt").write_text(
            f"url_enrich.json not found or empty at: {url_enrich_path}\n"
            f"Trying fallback from: {urls_txt}\n", encoding="utf-8"
        )
        try:
            if urls_txt.exists():
                lines = [ln.strip() for ln in urls_txt.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
                # ambil max 120
                lines = lines[:120]
                url_map = {u: {} for u in lines}
        except Exception as e:
            (debug_dir / "fallback_error.txt").write_text(str(e), encoding="utf-8")

    # kalau masih kosong, tulis file out kosong dengan catatan lalu kembali
    if not url_map:
        out = {
            "summary": {
                "model": os.environ.get("AI_MODEL","llama3.1:8b"),
                "counts": {"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0},
                "total_classified": 0,
                "total_source": 0,
                "note": f"No corpus. Missing: {url_enrich_path}"
            },
            "results": []
        }
        _save_json_atomic(cache / "ai_classify.json", out)
        return out

    pairs = sample_urls(url_map, max_items=120)
    block = _build_block(pairs)
    prompt = PROMPT.replace("{block}", block)

    if model_hint:
        os.environ["AI_MODEL"] = model_hint

    client = AIClient()
    raw = client.generate(prompt, temperature=0.1, max_tokens=1500)

    # simpan raw/prompt untuk debug SELALU
    (debug_dir / "last_prompt.txt").write_text(prompt or "", encoding="utf-8")
    (debug_dir / "last_raw.txt").write_text(raw or "", encoding="utf-8")

    # --- parsing lebih toleran ---
    results = []

    def _iter_json_objects(text: str):
        import re, json as _json
        if not text:
            return
        s = text.strip()
        # array penuh
        try:
            if s.startswith("[") and s.endswith("]"):
                arr = _json.loads(s)
                for obj in arr:
                    if isinstance(obj, dict):
                        yield obj
                return
        except Exception:
            pass
        # hapus code fences
        s = re.sub(r"```[\s\S]*?```", "", s)
        # cari semua {...}
        for m in re.finditer(r"\{[^{}]*\}", s, re.DOTALL):
            frag = m.group(0)
            try:
                obj = _json.loads(frag)
                if isinstance(obj, dict):
                    yield obj
            except Exception:
                continue

    for obj in _iter_json_objects(raw or ""):
        url    = obj.get("url")
        label  = (obj.get("label") or "INFO").upper()
        reason = obj.get("reason") or ""
        if url:
            if label not in ("HIGH","MEDIUM","LOW","INFO"):
                label = "INFO"
            results.append({"url": url, "label": label, "reason": reason})

    if not results:
        # fallback pola "url=..., label=HIGH, reason=..."
        for line in (raw or "").splitlines():
            line = line.strip()
            if "url=" in line and ("label=" in line or "risk=" in line):
                parts = {}
                for kv in line.replace(",", " ").split():
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        parts[k.strip().lower()] = v.strip()
                url = parts.get("url")
                lab = (parts.get("label") or parts.get("risk") or "INFO").upper()
                rea = parts.get("reason") or ""
                if url:
                    if lab not in ("HIGH","MEDIUM","LOW","INFO"):
                        lab = "INFO"
                    results.append({"url": url, "label": lab, "reason": rea})

    tally = {"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for r in results:
        tally[r["label"]] = tally.get(r["label"], 0) + 1

    out = {
        "summary": {
            "model": os.environ.get("AI_MODEL","llama3.1:8b"),
            "counts": tally,
            "total_classified": len(results),
            "total_source": len(url_map),
            "note": "No objects parsed; check ai_debug/last_raw.txt" if not results else ""
        },
        "results": results[:300]
    }
    _save_json_atomic(cache / "ai_classify.json", out)
    return out
