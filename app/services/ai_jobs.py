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

def _extract_search_keyword(query: str) -> Optional[str]:
    # 1. Cari string di dalam tanda kutip ganda atau tunggal
    m = re.findall(r'["\']([^"\']+)["\']', query)
    if m:
        return m[0].strip()

    # 2. Cari setelah kata "string", "kata", "mengandung"
    lower = query.lower()
    for pattern in [r"string\s+(\w+)", r"kata\s+(\w+)", r"mengandung\s+(\w+)"]:
        match = re.search(pattern, lower)
        if match:
            return match.group(1).strip()

    # 3. Cari kata benda/kata kerja spesifik yang dicari
    words = [w.strip("?,.!\n\r\"'") for w in query.split()]
    for w in words:
        if w.lower() in ("employer", "admin", "config", "api", "v1", "git", "env", "login"):
            return w

    return None

def _act_analyze(outputs_root: Path, scope: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Ringkas hasil klasifikasi jika ada, atau cari kecocokan kata kunci pada berkas temuan."""
    cache = _cache_dir(outputs_root, scope)
    root = outputs_root / scope

    query = args.get("query") or ""
    keyword = _extract_search_keyword(query) if query else None

    if keyword:
        keyword_lower = keyword.lower()
        matches: List[str] = []

        # 1. Scan urls.txt
        urls_file = root / "urls.txt"
        if urls_file.exists():
            for line in _read_lines(urls_file):
                if keyword_lower in line.lower():
                    matches.append(line)

        # 2. Scan subdomains.txt
        sub_file = root / "subdomains.txt"
        if sub_file.exists():
            for line in _read_lines(sub_file):
                if keyword_lower in line.lower():
                    matches.append(line)

        matches = _unique_sorted(matches)

        if matches:
            capped = matches[:15]
            items = "".join([f"<li><code>{_html_escape(m)}</code></li>" for m in capped])
            suffix = f"<li>... dan {len(matches) - 15} lainnya</li>" if len(matches) > 15 else ""

            return {
                "ok": True,
                "summary": {
                    "status": f"Ditemukan {len(matches)} hasil yang cocok untuk kata kunci '{keyword}':",
                    "message": f"<ul class='list-disc pl-5 mt-1 space-y-1'>{items}{suffix}</ul>"
                }
            }
        else:
            if urls_file.exists() or sub_file.exists():
                return {
                    "ok": True,
                    "summary": {
                        "status": f"Tidak ditemukan kecocokan untuk kata kunci '{keyword}'.",
                        "message": "Semua berkas temuan (urls.txt, subdomains.txt) telah diperiksa."
                    }
                }
            else:
                return {
                    "ok": True,
                    "summary": {
                        "status": "Berkas temuan kosong atau belum ada.",
                        "message": "Silakan jalankan pengumpulan subdomain/URL terlebih dahulu."
                    }
                }

    f = cache / "ai_classify.json"
    if not f.exists():
        subdomains = _collect_alive_subdomains(outputs_root, scope)
        return {
            "ok": True,
            "summary": {
                "status": f"Belum ada hasil klasifikasi AI mendalam. Terdeteksi {len(subdomains)} subdomain aktif saat ini.",
                "message": "Silakan jalankan pengumpulan URL (seperti GAU/Waymore) terlebih dahulu, lalu jalankan klasifikasi AI untuk laporan mendalam!"
            }
        }
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

def _act_ping(outputs_root: Path, scope: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Lakukan ping ke host/IP."""
    host = args.get("host") or args.get("ip") or "8.8.8.8"
    import subprocess
    try:
        # Gunakan opsi -c 3 untuk macOS/Linux (3 packets)
        res = subprocess.run(["ping", "-c", "3", host], capture_output=True, text=True, timeout=10)
        output = res.stdout + res.stderr
        ok = (res.returncode == 0)
        return {
            "ok": ok,
            "summary": {
                "status": f"Hasil ping ke {host}:",
                "message": f"<pre class='bg-slate-950 text-emerald-400 p-3 rounded font-mono text-xs max-h-[300px] overflow-y-auto max-w-full overflow-x-auto whitespace-pre-wrap mt-1 border border-slate-800 shadow-inner'>{_html_escape(output)}</pre>"
            }
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _act_execute_code(outputs_root: Path, scope: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Jalankan kode Python yang dibuat oleh AI secara dinamis (Code Interpreter)."""
    code = args.get("code") or ""
    if not code:
        return {"ok": False, "error": "No code provided"}

    # --- Guard Keamanan Sandbox Python ---
    code_lower = code.lower()
    dangerous_keywords = [
        "os.system", "subprocess", "eval(", "exec(", "shutil.rmtree", "os.remove", 
        "os.unlink", "os.rmdir", "os.chmod", "os.chown", "os.kill", "sys.exit",
        "import os", "import sys", "import shutil", "import subprocess", "__builtins__"
    ]
    for kw in dangerous_keywords:
        if kw in code_lower:
            return {
                "ok": False,
                "error": f"❌ Security Guard: Kata kunci berbahaya '{kw}' diblokir di Python Sandbox demi keamanan harddisk Anda!"
            }

    import sys
    import io
    import traceback

    # Siapkan environment yang kaya konteks untuk AI script (Hanya beri Path & json, sangat aman!)
    local_vars = {
        "outputs_root": outputs_root,
        "scope": scope,
        "target_dir": outputs_root / scope,
        "Path": Path,
        "json": json,
    }

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    redirected_output = io.StringIO()
    sys.stdout = redirected_output
    sys.stderr = redirected_output

    try:
        # Eksekusi script python
        exec(code, globals(), local_vars)
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        output = redirected_output.getvalue()
        return {
            "ok": True,
            "summary": {
                "status": "Hasil eksekusi kode AI (Code Interpreter):",
                "message": f"<pre class='bg-slate-950 text-emerald-400 p-3 rounded font-mono text-xs max-h-[300px] overflow-y-auto w-fit max-w-full block whitespace-pre overflow-x-auto mt-1 border border-slate-800 shadow-inner'>{_html_escape(output or 'Kode berhasil dijalankan tanpa output.')}</pre>"
            }
        }
    except Exception as e:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        tb = traceback.format_exc()
        return {
            "ok": False,
            "error": f"Error saat menjalankan kode:\n{tb}"
        }

def _act_run_command(outputs_root: Path, scope: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Jalankan perintah bash/shell secara dinamis."""
    cmd = args.get("command") or args.get("cmd") or ""
    if not cmd:
        return {"ok": False, "error": "No command provided"}

    # --- Guard Keamanan Sandbox Bash ---
    cmd_lower = cmd.lower().strip()
    dangerous_binaries = ["sudo", "rm ", "rm -", "mv ", "chmod ", "chown ", "dd ", "mkfs", "shutdown", "reboot", "poweroff"]
    for db in dangerous_binaries:
        if db in cmd_lower:
            return {
                "ok": False,
                "error": f"❌ Security Guard: Perintah berbahaya '{db}' diblokir di Bash Sandbox demi keamanan harddisk Anda!"
            }

    import subprocess
    try:
        # Batasi waktu eksekusi agar aman
        target_dir = outputs_root / scope
        target_dir.mkdir(parents=True, exist_ok=True)
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30, cwd=str(target_dir))
        output = res.stdout + res.stderr
        return {
            "ok": (res.returncode == 0),
            "summary": {
                "status": f"Hasil eksekusi perintah: <code>{_html_escape(cmd)}</code>",
                "message": f"<pre class='bg-slate-950 text-emerald-400 p-3 rounded font-mono text-xs max-h-[300px] overflow-y-auto w-fit max-w-full block whitespace-pre overflow-x-auto mt-1 border border-slate-800 shadow-inner'>{_html_escape(output or '[No Output]')}</pre>"
            }
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _act_save_script(outputs_root: Path, scope: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Simpan script yang dibuat AI ke dalam folder khusus target."""
    filename = args.get("filename") or args.get("name") or ""
    content = args.get("content") or args.get("code") or ""

    if not filename:
        return {"ok": False, "error": "Nama berkas script wajib disertakan."}
    if not content:
        return {"ok": False, "error": "Isi/konten script wajib disertakan."}

    # --- Guard Keamanan Jalur ---
    if ".." in filename or "/" in filename or "\\" in filename:
        return {"ok": False, "error": "❌ Security Guard: Path traversal terdeteksi dalam nama berkas!"}

    allowed_exts = (".py", ".sh", ".txt")
    if not any(filename.endswith(ext) for ext in allowed_exts):
        return {"ok": False, "error": f"❌ Security Guard: Hanya berkas dengan ekstensi {allowed_exts} yang diizinkan!"}

    # --- Guard Konten Script ---
    content_lower = content.lower()
    dangerous_keywords = ["shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "os.chmod", "os.chown", "os.kill", "sys.exit"]
    for kw in dangerous_keywords:
        if kw in content_lower:
            return {"ok": False, "error": f"❌ Security Guard: Konten mengandung kata kunci berbahaya '{kw}'!"}

    # Tulis berkas
    target_dir = outputs_root / scope
    scripts_dir = target_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    script_path = scripts_dir / filename
    try:
        script_path.write_text(content, encoding="utf-8")
        if filename.endswith(".sh"):
            import os
            try:
                os.chmod(str(script_path), 0o755)
            except Exception:
                pass
        return {
            "ok": True,
            "summary": {
                "status": f"Script berhasil disimpan!",
                "message": f"Berkas disimpan sebagai: <code>{_html_escape(str(script_path.relative_to(outputs_root)))}</code><br/>"
                           f"Anda sekarang dapat meminta AI untuk mengeksekusi script ini."
            }
        }
    except Exception as e:
        return {"ok": False, "error": f"Gagal menulis script: {str(e)}"}

def _act_execute_script(outputs_root: Path, scope: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Jalankan script yang tersimpan di folder khusus target."""
    filename = args.get("filename") or args.get("name") or ""
    script_args = args.get("args") or ""

    if not filename:
        return {"ok": False, "error": "Nama berkas script wajib disertakan."}

    # --- Guard Keamanan Jalur ---
    if ".." in filename or "/" in filename or "\\" in filename:
        return {"ok": False, "error": "❌ Security Guard: Path traversal terdeteksi dalam nama berkas!"}

    target_dir = outputs_root / scope
    script_path = target_dir / "scripts" / filename
    if not script_path.exists():
        return {"ok": False, "error": f"Berkas script '{filename}' tidak ditemukan di folder khusus target."}

    # Tentukan interpreter
    if filename.endswith(".py"):
        cmd = f"python3 {filename} {script_args}"
    elif filename.endswith(".sh"):
        cmd = f"./{filename} {script_args}"
    else:
        return {"ok": False, "error": "Hanya script .py dan .sh yang dapat dijalankan."}

    # --- Guard Keamanan Bash command ---
    cmd_lower = cmd.lower().strip()
    dangerous_binaries = ["sudo", "rm ", "rm -", "mv ", "chmod ", "chown ", "dd ", "mkfs", "shutdown", "reboot", "poweroff"]
    for db in dangerous_binaries:
        if db in cmd_lower:
            return {
                "ok": False,
                "error": f"❌ Security Guard: Perintah berbahaya '{db}' diblokir di Bash Sandbox demi keamanan harddisk Anda!"
            }

    import subprocess
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30, cwd=str(target_dir / "scripts"))
        output = res.stdout + res.stderr
        return {
            "ok": (res.returncode == 0),
            "summary": {
                "status": f"Hasil eksekusi script: <code>{_html_escape(cmd)}</code>",
                "message": f"<pre class='bg-slate-950 text-emerald-400 p-3 rounded font-mono text-xs max-h-[300px] overflow-y-auto w-fit max-w-full block whitespace-pre overflow-x-auto mt-1 border border-slate-800 shadow-inner'>{_html_escape(output or '[No Output]')}</pre>"
            }
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _act_subdomains_alive(outputs_root: Path, scope: str, args: Dict[str, Any]) -> Dict[str, Any]:
    hosts = _collect_alive_subdomains(outputs_root, scope)
    return {"ok": True, "alive": hosts, "count": len(hosts)}

# daftar tool & alias
ACTION_REGISTRY: Dict[str, Callable[[Path, str, Dict[str, Any]], Dict[str, Any]]] = {
    "analyze": _act_analyze,
    "subdomains_alive": _act_subdomains_alive,
    "ping": _act_ping,
    "execute_code": _act_execute_code,
    "run_command": _act_run_command,
    "bash": _act_run_command,
    "save_script": _act_save_script,
    "execute_script": _act_execute_script,
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
