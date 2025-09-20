# app/services/ai_jobs.py
from __future__ import annotations

import json, time, re
from pathlib import Path
from typing import Any, Dict, List, Callable, Optional, Tuple

CACHE_NAME_LAST_PLAN   = "ai_command_last_plan.json"
CACHE_NAME_JOB_STATUS  = "ai_jobs.json"  # status+logs terakhir

# ----------------- util path/cache -----------------

def _cache_dir(outputs_root: Path, scope: str) -> Path:
    d = outputs_root / scope / "__cache"
    d.mkdir(parents=True, exist_ok=True)
    return d

def save_last_plan(outputs_root: Path, scope: str, plan: Dict[str, Any]) -> Path:
    p = _cache_dir(outputs_root, scope) / CACHE_NAME_LAST_PLAN
    p.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    return p

def load_last_plan(outputs_root: Path, scope: str) -> Dict[str, Any] | None:
    p = _cache_dir(outputs_root, scope) / CACHE_NAME_LAST_PLAN
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None

def _job_status_path(outputs_root: Path, scope: str) -> Path:
    return _cache_dir(outputs_root, scope) / CACHE_NAME_JOB_STATUS

def _write_status(outputs_root: Path, scope: str, payload: Dict[str, Any]) -> None:
    _job_status_path(outputs_root, scope).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )

def _append_log(state: Dict[str, Any], msg: str) -> None:
    state.setdefault("logs", []).append({"ts": int(time.time()), "msg": msg})

# ----------------- helpers -----------------

_DOMAIN_RE = re.compile(r"^(?:https?://)?([^/]+)$")

def _host_from_any(s: str) -> Optional[str]:
    s = s.strip()
    if not s:
        return None
    # ambil host dari URL atau host polos
    m = _DOMAIN_RE.match(s)
    if m:
        return m.group(1).strip().lower()
    return None

def _read_lines(p: Path) -> List[str]:
    try:
        return [ln.strip() for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
    except Exception:
        return []

def _unique_sorted(items: List[str]) -> List[str]:
    return sorted(set(items), key=lambda x: (x.count("."), x))

# ----------------- actions -----------------

def _act_analyze(outputs_root: Path, scope: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Ringkas hasil klasifikasi jika ada."""
    cache = _cache_dir(outputs_root, scope)
    f = cache / "ai_classify.json"
    if not f.exists():
        return {"ok": False, "error": "ai_classify.json not found"}
    data = json.loads(f.read_text(encoding="utf-8"))
    return {"ok": True, "summary": data.get("summary", {})}

def _collect_alive_subdomains(outputs_root: Path, scope: str) -> List[str]:
    """
    Cari subdomain 'alive' dari beberapa sumber umum.
    Prioritas:
      1) __cache/subdomains_enrich.json (prefer alive==True; fallback code 200/301/302)
      2) __cache/subdomains_alive.txt
      3) subdomains/alive.txt
      4) subdomains.txt (fallback; tanpa filter alive)
    """
    root = outputs_root / scope

    # 1) enrich json
    enrich_json = _cache_dir(outputs_root, scope) / "subdomains_enrich.json"
    hosts: List[str] = []
    if enrich_json.exists():
        try:
            rows = json.loads(enrich_json.read_text(encoding="utf-8"))
            for r in rows if isinstance(rows, list) else []:
                host = r.get("host") or _host_from_any(r.get("url", "") or "")
                if not host:
                    continue
                alive = r.get("alive")
                code = r.get("code")
                if alive is True or (isinstance(code, int) and code in (200, 301, 302)):
                    hosts.append(host)
        except Exception:
            pass
    if hosts:
        return _unique_sorted(hosts)

    # 2) text list di cache
    f2 = _cache_dir(outputs_root, scope) / "subdomains_alive.txt"
    if f2.exists():
        hosts = [_host_from_any(x) or "" for x in _read_lines(f2)]
        return _unique_sorted([h for h in hosts if h])

    # 3) text list di folder subdomains
    f3 = root / "subdomains" / "alive.txt"
    if f3.exists():
        hosts = [_host_from_any(x) or "" for x in _read_lines(f3)]
        return _unique_sorted([h for h in hosts if h])

    # 4) fallback semua subdomain
    f4 = root / "subdomains.txt"
    if f4.exists():
        hosts = [_host_from_any(x) or "" for x in _read_lines(f4)]
        return _unique_sorted([h for h in hosts if h])

    return []

def _act_subdomains_alive(outputs_root: Path, scope: str, args: Dict[str, Any]) -> Dict[str, Any]:
    hosts = _collect_alive_subdomains(outputs_root, scope)
    return {"ok": True, "alive": hosts, "count": len(hosts)}

# daftar tool & alias
ACTION_REGISTRY: Dict[str, Callable[[Path, str, Dict[str, Any]], Dict[str, Any]]] = {
    "analyze": _act_analyze,
    "subdomains_alive": _act_subdomains_alive,
    # alias untuk parser yang mungkin memakai nama lain
    "list_active_subdomains": _act_subdomains_alive,
    "LIST_ACTIVE_SUBDOMAINS": _act_subdomains_alive,
}

# ----------------- runner -----------------

def run_plan_now(outputs_root: Path, scope: str, plan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Eksekusi plan secara sinkron. Menulis status/log ke __cache/ai_jobs.json.
    """
    state: Dict[str, Any] = {
        "ok": True,
        "status": "running",
        "scope": scope,
        "started_at": int(time.time()),
        "actions": [],
        "logs": [],
    }
    actions: List[Dict[str, Any]] = plan.get("actions") or []
    _append_log(state, f"Start plan with {len(actions)} action(s)")
    _write_status(outputs_root, scope, state)

    for idx, act in enumerate(actions, start=1):
        tool = (act.get("tool") or "").strip()
        args = act.get("args") or {}
        _append_log(state, f"[{idx}/{len(actions)}] {tool} ...")
        _write_status(outputs_root, scope, state)

        fn = ACTION_REGISTRY.get(tool) or ACTION_REGISTRY.get(tool.lower())
        if fn is None:
            res = {"ok": False, "error": f"Unknown tool: {tool}"}
        else:
            try:
                res = fn(outputs_root, scope, args)
            except Exception as e:
                res = {"ok": False, "error": str(e)}

        state["actions"].append({"tool": tool, "args": args, "result": res})
        _append_log(state, ("✅ " if res.get("ok") else "❌ ") + tool)
        _write_status(outputs_root, scope, state)

    state["status"] = "done"
    state["finished_at"] = int(time.time())
    _append_log(state, "Plan finished")
    _write_status(outputs_root, scope, state)
    return state

# ----------------- HTML wrapper (untuk UI percakapan) -----------------

def _html_escape(s: str) -> str:
    return (s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
              .replace('"',"&quot;").replace("'", "&#39;"))

def _render_subdomains_list(hosts: List[str]) -> str:
    if not hosts:
        return "<div>Active subdomains (0):</div>"
    items = "\n".join([f"<li><a href=\"http://{_html_escape(h)}\" target=\"_blank\" rel=\"noopener\">{_html_escape(h)}</a></li>"
                       for h in hosts])
    return f"""
      <div>Active subdomains ({len(hosts)}):</div>
      <ul class="list-disc ml-6 mt-1">{items}</ul>
    """

def run_plan_actions(outputs_root: Path, scope: str, plan: Dict[str, Any]) -> str:
    """
    Wrapper: jalankan plan lalu kembalikan HTML ringkas untuk UI.
    """
    state = run_plan_now(outputs_root, scope, plan)
    parts: List[str] = []
    parts.append("<div>Plan executed.</div>")

    for a in state.get("actions", []):
        tool = a.get("tool") or ""
        res = a.get("result") or {}
        ok = res.get("ok")
        parts.append(f"<div class='mt-2 font-medium'>{_html_escape(tool)} — {'OK' if ok else 'FAILED'}</div>")
        if not ok:
            parts.append(f"<div class='text-rose-600 text-sm'>{_html_escape(str(res.get('error','error')))}</div>")
            continue

        # khusus subdomains
        if tool in ("subdomains_alive", "list_active_subdomains", "LIST_ACTIVE_SUBDOMAINS"):
            hosts = res.get("alive") or []
            parts.append(_render_subdomains_list(hosts))
        else:
            # generic JSON
            pretty = _html_escape(json.dumps(res, ensure_ascii=False, indent=2))
            parts.append(f"<pre class='text-xs bg-slate-50 border rounded p-2 overflow-auto'>{pretty}</pre>")

    return "\n".join(parts)

# ----------------- current plan helpers (opsional) -----------------

def _jobs_dir(outputs_root: Path, scope: str) -> Path:
    d = outputs_root / scope / "__cache" / "ai_jobs"
    d.mkdir(parents=True, exist_ok=True)
    return d

def plan_path(outputs_root: Path, scope: str) -> Path:
    return _jobs_dir(outputs_root, scope) / "plan.json"

def set_current_plan(outputs_root: Path, scope: str, plan: Dict[str, Any]) -> None:
    p = plan_path(outputs_root, scope)
    p.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")

def get_current_plan(outputs_root: Path, scope: str) -> Optional[Dict[str, Any]]:
    p = plan_path(outputs_root, scope)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def clear_current_plan(outputs_root: Path, scope: str) -> None:
    p = plan_path(outputs_root, scope)
    if p.exists():
        p.unlink(missing_ok=True)
