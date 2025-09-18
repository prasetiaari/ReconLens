# app/services/ai_rules.py
from __future__ import annotations

import json, re, random
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

LABELS = ("HIGH", "MEDIUM", "LOW", "INFO")

# ---------- IO helpers ----------

def _read_json(p: Path) -> dict:
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def _write_json_atomic(p: Path, data: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)

def _urls_txt(outputs_root: Path, scope: str) -> Path:
    return outputs_root / scope / "urls.txt"

def _url_enrich(outputs_root: Path, scope: str) -> Path:
    return outputs_root / scope / "__cache" / "url_enrich.json"

def _cache_dir(outputs_root: Path, scope: str) -> Path:
    return outputs_root / scope / "__cache"

def _ai_seed_path(outputs_root: Path, scope: str) -> Path:
    return _cache_dir(outputs_root, scope) / "ai_rules.seed.json"

def _ai_custom_path(outputs_root: Path, scope: str) -> Path:
    return _cache_dir(outputs_root, scope) / "ai_rules.custom.json"

def _ai_out_path(outputs_root: Path, scope: str) -> Path:
    return _cache_dir(outputs_root, scope) / "ai_classify.json"

# ---------- corpus loaders ----------

def load_urls(outputs_root: Path, scope: str, limit: Optional[int] = None) -> List[str]:
    p = _urls_txt(outputs_root, scope)
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

def load_enrich_map(outputs_root: Path, scope: str) -> Dict[str, Any]:
    return _read_json(_url_enrich(outputs_root, scope)) or {}

# ---------- rules ----------

def _compile_rule(r: dict) -> dict:
    rr = dict(r)
    pat = rr.get("pattern") or ".*"
    rr["_re"] = re.compile(pat, re.IGNORECASE)
    if isinstance(rr.get("method"), str):
        rr["method"] = [rr["method"]]
    return rr

def load_rules(outputs_root: Path, scope: str) -> Tuple[str, List[dict]]:
    seed = _read_json(_ai_seed_path(outputs_root, scope)).get("rules") or []
    custom = _read_json(_ai_custom_path(outputs_root, scope)).get("rules") or []

    merged: Dict[str, dict] = {}
    for r in seed:
        if isinstance(r, dict) and r.get("id"):
            merged[r["id"]] = r
    for r in custom:
        if isinstance(r, dict) and r.get("id"):
            merged[r["id"]] = r

    compiled = [_compile_rule(v) for v in merged.values()]
    version = "seed+custom" if custom else "seed"
    return version, compiled

# ---------- matching ----------

def _matches_rule(url: str, rec: Optional[dict], rule: dict) -> bool:
    if not rule["_re"].search(url):
        return False
    if rule.get("method"):
        m = (rec or {}).get("mode") or (rec or {}).get("method")
        if not m or str(m).upper() not in [x.upper() for x in rule["method"]]:
            return False
    if rule.get("host_contains"):
        host = _safe_host(url)
        if rule["host_contains"].lower() not in host.lower():
            return False
    if rule.get("path_contains"):
        path = _safe_path(url)
        if rule["path_contains"].lower() not in path.lower():
            return False
    if rule.get("code_in"):
        code = (rec or {}).get("code")
        try:
            code_i = int(code) if code is not None else None
        except Exception:
            code_i = None
        if code_i not in set(rule["code_in"]):
            return False
    return True

def _safe_host(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return (urlparse(url).netloc or "").lower()
    except Exception:
        return ""

def _safe_path(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return (urlparse(url).path or "/")
    except Exception:
        return "/"

def _demote_by_http(label: str, rec: Optional[dict], demote_blocked: bool, demote_404: bool) -> str:
    if not rec:
        return label
    try:
        code = int(rec.get("code")) if rec.get("code") is not None else None
    except Exception:
        code = None
    if code is None:
        return label
    if demote_blocked and code in (401, 403):
        return "INFO"
    if demote_404 and code == 404:
        return "INFO"
    return label

# ---------- engine ----------

def apply_rules(
    outputs_root: Path,
    scope: str,
    limit: Optional[int] = None,
    demote_blocked: bool = True,
    demote_404: bool = True,
    save_result: bool = True,
) -> dict:
    rules_version, rules = load_rules(outputs_root, scope)
    urls = load_urls(outputs_root, scope, limit=None)
    enrich_map = load_enrich_map(outputs_root, scope)

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    results: List[dict] = []

    for url in urls:
        rec = enrich_map.get(url) or enrich_map.get(url.rstrip("/")) or enrich_map.get(url + "/")
        matched = None
        for r in rules:
            if _matches_rule(url, rec, r):
                matched = r
                break
        if matched:
            label = str(matched.get("label") or "INFO").upper()
            if label not in LABELS:
                label = "INFO"
            label = _demote_by_http(label, rec, demote_blocked, demote_404)
            counts[label] = counts.get(label, 0) + 1
            results.append({
                "url": url,
                "rule_id": matched.get("id") or "?",
                "label": str(matched.get("label") or "INFO").upper(),
                "reason": matched.get("reason") or "",
                "final_label": label,
                "code": (rec or {}).get("code"),
            })

    sample = _balanced_sample(results, max_total=1000)

    out = {
        "summary": {
            "rules_version": rules_version,
            "rules_file": str(_ai_seed_path(outputs_root, scope)),
            "counts": counts,
            "total_classified": sum(counts.values()),
            "total_source": len(urls),
            "note": "Applied rules with HTTP demotion policy",
        },
        "results_sample": sample,
    }

    if save_result:
        _write_json_atomic(_ai_out_path(outputs_root, scope), out)
    return out

def preview_rules(
    outputs_root: Path,
    scope: str,
    limit: int = 500,
    demote_blocked: bool = True,
    demote_404: bool = True,
) -> dict:
    rules_version, rules = load_rules(outputs_root, scope)
    full = load_urls(outputs_root, scope, limit=None)
    if not full:
        return {"summary": {"rules_version": rules_version, "limit": 0, "counts": {}}}

    rnd = list(full)
    random.shuffle(rnd)
    sample_urls = rnd[: max(1, min(limit, len(rnd)))]

    enrich_map = load_enrich_map(outputs_root, scope)
    per_rule: Dict[str, dict] = {}
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for url in sample_urls:
        rec = enrich_map.get(url) or enrich_map.get(url.rstrip("/")) or enrich_map.get(url + "/")
        for r in rules:
            if _matches_rule(url, rec, r):
                label = str(r.get("label") or "INFO").upper()
                final = _demote_by_http(label, rec, demote_blocked, demote_404)
                rid = r.get("id") or "?"
                bucket = per_rule.setdefault(rid, {
                    "id": rid,
                    "label": label,
                    "reason": r.get("reason") or "",
                    "hits": 0,
                    "samples": [],
                })
                bucket["hits"] += 1
                if len(bucket["samples"]) < 5:
                    bucket["samples"].append({"url": url, "final_label": final})
                counts[final] = counts.get(final, 0) + 1
                break

    return {
        "summary": {
            "rules_version": rules_version,
            "limit": len(sample_urls),
            "counts": counts,
        },
        "rules": sorted(per_rule.values(), key=lambda x: (-x["hits"], x["id"])),
    }

# ---------- utils ----------

def _balanced_sample(rows: List[dict], max_total: int = 1000) -> List[dict]:
    by_lbl: Dict[str, List[dict]] = {k: [] for k in LABELS}
    for r in rows:
        by_lbl.setdefault(r.get("final_label", "INFO"), []).append(r)

    quotas = {
        "HIGH": max_total // 10,
        "MEDIUM": max_total // 3,
        "LOW": max_total // 3,
        "INFO": max_total - (max_total // 10) - (max_total // 3) * 2,
    }

    out: List[dict] = []
    for k, lst in by_lbl.items():
        random.shuffle(lst)
        out.extend(lst[: quotas.get(k, 0)])
    return out[:max_total]
