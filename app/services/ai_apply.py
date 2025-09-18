# app/services/ai_apply.py
from __future__ import annotations
import json, re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ====== Helpers & paths ======

def _cache_dir(outputs_root: Path, scope: str) -> Path:
    p = outputs_root / scope / "__cache"
    p.mkdir(parents=True, exist_ok=True)
    return p

def _path_url_enrich(outputs_root: Path, scope: str) -> Path:
    return _cache_dir(outputs_root, scope) / "url_enrich.json"

def _path_ai_classify(outputs_root: Path, scope: str) -> Path:
    return _cache_dir(outputs_root, scope) / "ai_classify.json"

def _path_seed_rules() -> Path:
    # sesuaikan bila lokasi seed-mu berbeda
    return Path(__file__).resolve().parent.parent / "data" / "ai_rules.seed.json"

def _path_custom_rules(outputs_root: Path, scope: str) -> Path:
    return _cache_dir(outputs_root, scope) / "custom_rules.json"

def _path_ai_rules(outputs_root: Path, scope: str) -> Path:
    return _cache_dir(outputs_root, scope) / "ai_rules.generated.json"

def _safe_load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

# ====== Load rules by source ======

def _rules_from_file(path: Path) -> List[dict]:
    data = _safe_load_json(path)
    if not data:
        return []
    if isinstance(data, list):
        return _normalize_rules(data)
    # kalau ada bentuk {"rules":[...]}
    if isinstance(data, dict) and isinstance(data.get("rules"), list):
        return _normalize_rules(data["rules"])
    return []

def load_seed_rules() -> List[dict]:
    return _rules_from_file(_path_seed_rules())

def load_custom_rules(outputs_root: Path, scope: str) -> List[dict]:
    return _rules_from_file(_path_custom_rules(outputs_root, scope))

def load_ai_rules(outputs_root: Path, scope: str) -> List[dict]:
    return _rules_from_file(_path_ai_rules(outputs_root, scope))

# ====== Normalization & validation ======

_VALID_LABELS = {"HIGH","MEDIUM","LOW","INFO"}

def _normalize_rules(rules: List[dict]) -> List[dict]:
    out = []
    for r in rules:
        try:
            rid = str(r.get("id") or "").strip() or "rule"
            lbl = str(r.get("label") or "").upper().strip()
            if lbl not in _VALID_LABELS:
                continue
            reason = str(r.get("reason") or "").strip() or lbl
            pattern = str(r.get("pattern") or "").strip()
            if not pattern:
                continue
            code_in = r.get("code_in")
            if code_in is None:
                # default: kalau tak disediakan, anggap cocok untuk code 200-499
                code_in = []
            elif not isinstance(code_in, list):
                code_in = []
            else:
                code_in = [int(x) for x in code_in if isinstance(x, (int, float, str)) and str(x).isdigit()]
            out.append({
                "id": rid,
                "label": lbl,
                "reason": reason,
                "pattern": pattern,
                "code_in": code_in,
            })
        except Exception:
            continue
    return out

def _severity_weight(label: str) -> int:
    return {"HIGH":4, "MEDIUM":3, "LOW":2, "INFO":1}.get(label.upper(), 0)

# ====== Compilation ======

@dataclass
class CompiledRule:
    id: str
    label: str
    reason: str
    regex: re.Pattern
    code_in: List[int]
    source: str  # "seed" | "custom" | "ai"

def compile_rules(rules: List[dict], source: str) -> List[CompiledRule]:
    out: List[CompiledRule] = []
    for r in rules:
        try:
            rx = re.compile(r["pattern"], re.IGNORECASE)
            out.append(CompiledRule(
                id=r["id"],
                label=r["label"],
                reason=r["reason"],
                regex=rx,
                code_in=r.get("code_in", []) or [],
                source=source,
            ))
        except Exception:
            # skip invalid regex
            continue
    return out

# ====== Core Apply ======

@dataclass
class ApplyOptions:
    demote_if_no_code: bool = True
    http_required: bool = False  # kalau True, hanya URL yang punya code yang dinilai
    sample_limit: int = 500      # berapa baris dimasukkan ke results_sample
    limit_sample: Optional[int] = None

def _maybe_demote(label: str) -> str:
    # turunkan 1 tingkat: HIGH->MEDIUM->LOW->INFO
    steps = ["INFO","LOW","MEDIUM","HIGH"]
    idx = steps.index(label) if label in steps else 0
    return steps[max(0, idx-1)]

def apply_rules(
    outputs_root: Path,
    scope: str,
    sources: List[str],  # contoh: ["seed","custom","ai"]
    options: Optional[ApplyOptions] = None,
) -> Dict[str, Any]:
    """
    Terapkan rules ke korpus URL (url_enrich.json atau fallback urls.txt).
    - Mendukung demotion ketika HTTP code tidak ada (options.demote_if_no_code).
    - Mendukung pembatasan jumlah URL yang diproses (options.limit_sample) agar cepat untuk preview.
    - Menggabungkan beberapa sumber rules; jika bentrok, severity tertinggi menang, kalau sama
      pakai prioritas sumber: custom > ai > seed.
    - Tulis hasil ringkas ke __cache/ai_classify.json untuk ditampilkan di UI.
    """
    options = options or ApplyOptions()
    cache_dir = _cache_dir(outputs_root, scope)  # noqa: F841 (disiapkan untuk future use)

    # 1) load korpus URL
    url_map = _safe_load_json(_path_url_enrich(outputs_root, scope)) or {}
    if not url_map:
        urls_txt = outputs_root / scope / "urls.txt"
        if urls_txt.exists():
            lines = [
                ln.strip()
                for ln in urls_txt.read_text(encoding="utf-8", errors="ignore").splitlines()
                if ln.strip()
            ]
            url_map = {ln: {} for ln in lines}

    if not url_map:
        return {"ok": False, "error": "No URL corpus (url_enrich.json or urls.txt)"}

    total_source = len(url_map)

    # 2) load & compile rules dari sumber-sumber yang dipilih
    rules_all: List[CompiledRule] = []
    if "seed" in sources:
        rules_all += compile_rules(load_seed_rules(), "seed")
    if "custom" in sources:
        rules_all += compile_rules(load_custom_rules(outputs_root, scope), "custom")
    if "ai" in sources:
        rules_all += compile_rules(load_ai_rules(outputs_root, scope), "ai")

    if not rules_all:
        return {"ok": False, "error": "No rules for selected sources"}

    # 3) apply
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    classified: List[dict] = []

    # prioritas sumber (dipakai jika severity sama)
    source_prio = {"custom": 3, "ai": 2, "seed": 1}

    def better(curr: Optional[Tuple[int, int]], cand_label: str, cand_src_tag: str) -> bool:
        """
        Bandingkan kandidat (label, sumber).
        curr: tuple (severity_weight, source_priority) dari kandidat terbaik saat ini.
        Kembalikan True jika kandidat baru lebih baik.
        """
        sev = _severity_weight(cand_label)
        srcp = source_prio.get(cand_src_tag, 0)
        if curr is None:
            return True
        c_sev, c_srcp = curr
        if sev != c_sev:
            return sev > c_sev
        return srcp > c_srcp

    # batasi jumlah URL yang diproses untuk preview bila diminta
    items = list(url_map.items())
    if getattr(options, "limit_sample", None):
        items = items[: int(options.limit_sample)]

    for url, rec in items:
        # HTTP code (jika ada)
        code = rec.get("code")
        try:
            code_i = int(code) if code is not None else None
        except Exception:
            code_i = None

        # jika require HTTP code, skip yang tidak punya
        if getattr(options, "http_required", False) and code_i is None:
            continue

        best_tuple: Optional[Tuple[int, int]] = None
        best_label: Optional[str] = None
        best_reason: Optional[str] = None
        best_src_tag: Optional[str] = None  # 'seed'/'custom'/'ai'
        best_rule_id: Optional[str] = None  # id rule spesifik

        for rule in rules_all:
            # filter berdasarkan code_in jika di-rule dipasang
            if rule.code_in and code_i is not None and code_i not in rule.code_in:
                continue

            # cocokkan regex terhadap URL
            if not rule.regex.search(url):
                continue

            lab = rule.label
            # demote jika tidak ada HTTP code & opsi aktif
            if options.demote_if_no_code and code_i is None:
                lab = _maybe_demote(lab)

            if better(best_tuple, lab, rule.source):
                best_tuple = (_severity_weight(lab), source_prio.get(rule.source, 0))
                best_label = lab
                best_reason = rule.reason
                best_src_tag = rule.source
                best_rule_id = rule.id

        if best_label:
            row = {
                "url": url,
                "label": best_label,
                "reason": best_reason,
                "final_label": best_label,
                "final_reason": best_reason,
                "source": best_src_tag,
                "rule_id": best_rule_id,
                "code": code_i,
            }
            classified.append(row)

    # 4) ringkas
    for row in classified:
        lbl = row["label"]
        if lbl in counts:
            counts[lbl] += 1

    summary = {
        "rules_version": "+".join(sources) if sources else "none",
        "counts": counts,
        "total_classified": sum(counts.values()),
        "total_source": total_source,
        "note": "Applied rules"
        + (" with HTTP demotion" if options.demote_if_no_code else "")
        + (f"; limited to {len(items)} URLs" if getattr(options, "limit_sample", None) else ""),
    }

    # hasil yang disimpan untuk UI (kalau limit_sample aktif, memang sudah terbatas)
    results_to_save = classified
    if getattr(options, "limit_sample", None):
        # jaga2 bila di masa depan proses tidak membatasi di depan
        results_to_save = classified[: int(options.limit_sample)]

    out = {
        "summary": summary,
        "results": results_to_save,
    }

    # 5) tulis ke disk
    _path_ai_classify(outputs_root, scope).write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    return {"ok": True, **out}
