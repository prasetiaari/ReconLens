#!/usr/bin/env python3
# ReconLens/tools/passive_recon.py
"""
Orchestrator for Full Passive Reconnaissance pipeline.
Runs subdomain gathering, URL harvesting, and module classification in sequence.
Emits structured events to stdout for the workflow dashboard UI.
Supports checkpoint-based resume after interruption.
"""
import argparse
import sys
import os
import json
import subprocess
import signal
from pathlib import Path
from datetime import datetime

# Setup sys.path to allow absolute imports from app
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

active_process = None
paused = False

# ── Step definitions ──────────────────────────────────────────────────────────

STEPS = [
    {"name": "subfinder",         "label": "Subdomain: Subfinder",       "phase": "subdomains", "type": "cmd",  "critical": False},
    {"name": "amass",             "label": "Subdomain: Amass (passive)", "phase": "subdomains", "type": "cmd",  "critical": False},
    {"name": "findomain",         "label": "Subdomain: Findomain",       "phase": "subdomains", "type": "cmd",  "critical": False},
    {"name": "merge_subdomains",  "label": "Deduplicate Subdomains",     "phase": "subdomains", "type": "func", "critical": True},
    {"name": "gau",               "label": "URL: GAU",                   "phase": "urls",       "type": "cmd",  "critical": False},
    {"name": "waymore",           "label": "URL: Waymore",               "phase": "urls",       "type": "cmd",  "critical": False},
    {"name": "urlfinder",         "label": "URL: URLFinder",             "phase": "urls",       "type": "cmd",  "critical": False},
    {"name": "merge_urls",        "label": "Deduplicate URLs",           "phase": "urls",       "type": "func", "critical": True},
    {"name": "build",             "label": "Build Modules (classify)",   "phase": "build",      "type": "func", "critical": True},
]


# ── Signal handling ───────────────────────────────────────────────────────────

def signal_handler(sig, frame):
    emit_log("[info] SIGINT/SIGTERM received. Terminating running subprocess...")
    global active_process
    if active_process:
        try:
            active_process.terminate()
            active_process.wait(timeout=5)
        except Exception:
            pass
    emit_log("[info] Subprocess terminated. Exiting.")
    sys.exit(1)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ── Event emitters ────────────────────────────────────────────────────────────

def emit_step_update(name: str, status: str, index: int, total: int):
    """Emit a step status change event."""
    payload = json.dumps({"name": name, "status": status, "index": index, "total": total})
    print(f"[step_update] {payload}", flush=True)

def emit_progress(done: int, total: int):
    """Emit a global progress event."""
    pct = int((done / total) * 100) if total > 0 else 0
    payload = json.dumps({"done": done, "total": total, "percentage": pct})
    print(f"[progress] {payload}", flush=True)

def emit_log(msg: str):
    """Emit a regular log line."""
    print(msg, flush=True)


# ── Tool binary resolution ───────────────────────────────────────────────────

def get_tool_binary(name: str) -> str:
    config_path = project_root / "app" / "config" / "config.yaml"
    if config_path.exists():
        try:
            import yaml
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
                path = cfg.get("tools", {}).get(name)
                if path:
                    return path
        except Exception:
            pass
    return name


# ── Checkpoint management ────────────────────────────────────────────────────

def checkpoint_path(out_dir: Path) -> Path:
    return out_dir / "__cache" / "passive_recon_state.json"

def load_checkpoint(out_dir: Path) -> dict:
    p = checkpoint_path(out_dir)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8")) or {}
        except Exception:
            pass
    return {"completed_steps": [], "status": "pending"}

def save_checkpoint(out_dir: Path, state: dict):
    cache_dir = out_dir / "__cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    p = checkpoint_path(out_dir)
    p.write_text(json.dumps(state, indent=2), encoding="utf-8")

def clear_checkpoint(out_dir: Path):
    p = checkpoint_path(out_dir)
    if p.exists():
        p.unlink()


# ── Command execution ────────────────────────────────────────────────────────

def build_step_cmd(step_name: str, scope: str, raw_dir: Path) -> list[str]:
    """Build the command list for a given tool step."""
    cmds = {
        "subfinder": [get_tool_binary("subfinder"), "-d", scope, "-silent", "-all"],
        "amass":     [get_tool_binary("amass"), "enum", "-passive", "-timeout", "15", "-d", scope],
        "findomain": [get_tool_binary("findomain"), "--target", scope, "--quiet"],
        "gau":       [get_tool_binary("gau"), "--verbose", scope],
        "waymore":   [
            get_tool_binary("waymore"),
            "-i", scope, "-mode", "U",
            "-oU", str(raw_dir / "waymore_temp.urls"),
            "--verbose"
        ],
        "urlfinder": [get_tool_binary("urlfinder"), "-d", scope, "-all"],
    }
    return cmds.get(step_name, [])

def run_cmd_step(name: str, cmd: list[str], raw_dir: Path) -> int:
    """Execute an external tool, streaming output to stdout and saving to raw file."""
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    raw_path = raw_dir / f"{name}-{timestamp}.urls"

    emit_log(f"\n$ {' '.join(cmd)}")
    emit_log(f"[info] Output saved to: {raw_path}")

    global active_process
    with open(raw_path, "w", encoding="utf-8") as raw_f:
        active_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        for line in active_process.stdout:
            raw_f.write(line)
            sys.stdout.write(line)
            sys.stdout.flush()
        active_process.wait()

    code = active_process.returncode
    active_process = None
    emit_log(f"[info] {name} finished (exit code: {code})")
    return code


# ── Internal merge/build functions ────────────────────────────────────────────

def merge_subdomains_step(scope: str, out_dir: Path, raw_dir: Path):
    target = out_dir / "subdomains.txt"
    raw_files = (
        list(raw_dir.glob("subfinder-*.urls")) +
        list(raw_dir.glob("amass-*.urls")) +
        list(raw_dir.glob("findomain-*.urls"))
    )
    if not raw_files:
        emit_log("[info] No raw subdomain files found to merge.")
        return

    emit_log(f"[info] Merging {len(raw_files)} raw subdomain files into subdomains.txt...")
    tmp_incoming = out_dir / "subdomains_incoming.tmp"

    unique_lines = set()
    for p in raw_files:
        try:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if s:
                    unique_lines.add(s)
        except Exception as e:
            emit_log(f"[warn] Failed to read {p}: {e}")

    tmp_incoming.write_text("\n".join(sorted(unique_lines)) + "\n", encoding="utf-8")

    from app.routers.targets.utils import merge_hostnames
    merge_hostnames(target, tmp_incoming)

    if tmp_incoming.exists():
        tmp_incoming.unlink()

    final_count = sum(1 for _ in target.read_text(encoding="utf-8", errors="ignore").splitlines() if _.strip()) if target.exists() else 0
    emit_log(f"[info] Subdomain merge complete. Total unique: {final_count}")


def merge_urls_step(scope: str, out_dir: Path, raw_dir: Path):
    target = out_dir / "urls.txt"
    raw_files = (
        list(raw_dir.glob("gau-*.urls")) +
        list(raw_dir.glob("waymore-*.urls")) +
        list(raw_dir.glob("urlfinder-*.urls"))
    )
    if not raw_files:
        emit_log("[info] No raw URL files found to merge.")
        return

    emit_log(f"[info] Merging {len(raw_files)} raw URL files into urls.txt...")
    tmp_incoming = out_dir / "urls_incoming.tmp"

    unique_lines = set()
    for p in raw_files:
        try:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if s:
                    unique_lines.add(s)
        except Exception as e:
            emit_log(f"[warn] Failed to read {p}: {e}")

    tmp_incoming.write_text("\n".join(sorted(unique_lines)) + "\n", encoding="utf-8")

    from app.routers.targets.utils import merge_urls
    merge_urls(target, tmp_incoming)

    if tmp_incoming.exists():
        tmp_incoming.unlink()

    final_count = sum(1 for _ in target.read_text(encoding="utf-8", errors="ignore").splitlines() if _.strip()) if target.exists() else 0
    emit_log(f"[info] URL merge complete. Total unique: {final_count}")


def build_modules_step(scope: str, out_dir: Path, raw_dir: Path):
    emit_log("[info] Starting modules classification build...")
    main_py = project_root / "__main__.py"
    cmd = [sys.executable, str(main_py), "--scope", scope, "--input", str(out_dir / "urls.txt"), "--out", str(out_dir)]
    emit_log(f"$ {' '.join(cmd)}")

    global active_process
    active_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in active_process.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
    active_process.wait()

    code = active_process.returncode
    active_process = None
    emit_log(f"[info] Module builder finished (exit code: {code})")
    if code != 0:
        raise RuntimeError(f"Module builder failed with code {code}")

# Map function step names to their implementations
FUNC_MAP = {
    "merge_subdomains": merge_subdomains_step,
    "merge_urls": merge_urls_step,
    "build": build_modules_step,
}


# ── Main pipeline ────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Passive Recon Pipeline Orchestrator")
    p.add_argument("--scope", required=True, help="Target root domain")
    p.add_argument("--outputs", required=True, help="Path to outputs directory")
    p.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
    args = p.parse_args()

    out_dir = Path(args.outputs) / args.scope
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    total_steps = len(STEPS)

    # Load checkpoint
    state = load_checkpoint(out_dir)
    completed = set(state.get("completed_steps", []))

    if not args.resume:
        # Fresh run: clear old checkpoint
        completed = set()
        state = {"completed_steps": [], "status": "running"}
        save_checkpoint(out_dir, state)

    emit_log(f"=== Passive Recon Pipeline: {args.scope} ===")
    emit_log(f"[info] Total steps: {total_steps}")

    # Emit initial state for all steps
    for i, step in enumerate(STEPS):
        name = step["name"]
        if name in completed:
            emit_step_update(name, "completed", i, total_steps)
        else:
            emit_step_update(name, "pending", i, total_steps)

    emit_progress(len(completed), total_steps)

    for i, step in enumerate(STEPS):
        name = step["name"]

        if name in completed:
            emit_log(f"[info] Skipping '{step['label']}' (already completed)")
            continue

        # Mark running
        emit_step_update(name, "running", i, total_steps)

        success = False
        if step["type"] == "cmd":
            cmd = build_step_cmd(name, args.scope, raw_dir)
            if not cmd:
                emit_log(f"[warn] No command defined for '{name}', skipping.")
                emit_step_update(name, "skipped", i, total_steps)
                success = True
            else:
                exit_code = run_cmd_step(name, cmd, raw_dir)
                if exit_code == 0:
                    success = True
                elif not step.get("critical", False):
                    emit_log(f"[warn] '{step['label']}' failed (exit {exit_code}), but it's non-critical. Continuing...")
                    emit_step_update(name, "failed", i, total_steps)
                    success = True  # Continue despite failure for non-critical tools
                else:
                    emit_log(f"[error] '{step['label']}' failed (exit {exit_code}). Halting pipeline.")
                    emit_step_update(name, "failed", i, total_steps)
                    state["status"] = "failed"
                    save_checkpoint(out_dir, state)
                    sys.exit(exit_code)

        elif step["type"] == "func":
            func = FUNC_MAP.get(name)
            if not func:
                emit_log(f"[warn] No function defined for '{name}', skipping.")
                success = True
            else:
                try:
                    func(args.scope, out_dir, raw_dir)
                    success = True
                except Exception as e:
                    emit_log(f"[error] '{step['label']}' failed: {e}")
                    emit_step_update(name, "failed", i, total_steps)
                    if step.get("critical", False):
                        state["status"] = "failed"
                        save_checkpoint(out_dir, state)
                        sys.exit(1)
                    else:
                        success = True  # Continue for non-critical

        if success:
            if name not in [s["name"] for s in STEPS if s["type"] == "cmd" and not success]:
                emit_step_update(name, "completed", i, total_steps)

            completed.add(name)
            state["completed_steps"] = list(completed)
            state["status"] = "running"
            save_checkpoint(out_dir, state)
            emit_progress(len(completed), total_steps)

    # Pipeline complete
    clear_checkpoint(out_dir)
    emit_log("\n=== Passive Recon Pipeline Completed Successfully ===")


if __name__ == "__main__":
    main()
