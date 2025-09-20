from __future__ import annotations
import json, time, uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any

@dataclass
class Msg:
    role: str                # "user" | "assistant" | "system" | "tool"
    content: str             # plain/markdown/html ringkas
    ts: float                # epoch seconds
    meta: Optional[Dict[str, Any]] = None  # e.g. {"kind":"plan","plan_path": "..."}
    id: str = ""

    @staticmethod
    def new(role: str, content: str, meta: Optional[Dict[str, Any]] = None) -> "Msg":
        return Msg(role=role, content=content, ts=time.time(), meta=meta or {}, id=str(uuid.uuid4())[:8])

@dataclass
class ThreadInfo:
    id: str
    title: str
    created_at: float
    updated_at: float
    msg_count: int = 0

class AiCmdStore:
    def __init__(self, outputs_root: Path, scope: str):
        self.root = Path(outputs_root) / scope / "__cache" / "ai_cmd"
        self.root.mkdir(parents=True, exist_ok=True)
        self.idx_path = self.root / "threads.json"

    # ---------- index ----------
    def _load_index(self) -> Dict[str, ThreadInfo]:
        if not self.idx_path.exists():
            return {}
        data = json.loads(self.idx_path.read_text(encoding="utf-8") or "{}")
        out: Dict[str, ThreadInfo] = {}
        for tid, v in data.items():
            out[tid] = ThreadInfo(**v)
        return out

    def _save_index(self, idx: Dict[str, ThreadInfo]) -> None:
        self.idx_path.write_text(
            json.dumps({k: asdict(v) for k, v in idx.items()}, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    # ---------- thread/files ----------
    def _thread_file(self, tid: str) -> Path:
        return self.root / f"thread_{tid}.jsonl"

    def _plan_file(self, tid: str) -> Path:
        return self.root / f"last_plan_{tid}.json"

    def list_threads(self) -> List[ThreadInfo]:
        idx = self._load_index()
        return sorted(idx.values(), key=lambda x: x.updated_at, reverse=True)

    def create_thread(self, title: str) -> ThreadInfo:
        tid = time.strftime("%Y%m%d") + "-" + str(uuid.uuid4())[:8]
        info = ThreadInfo(id=tid, title=title.strip() or "New chat", created_at=time.time(), updated_at=time.time())
        idx = self._load_index()
        idx[tid] = info
        self._save_index(idx)
        self._thread_file(tid).touch()
        return info

    def append_msg(self, tid: str, msg: Msg) -> None:
        line = json.dumps(asdict(msg), ensure_ascii=False)
        self._thread_file(tid).write_text(
            (self._thread_file(tid).read_text(encoding="utf-8") if self._thread_file(tid).exists() else "") + line + "\n",
            encoding="utf-8"
        )
        idx = self._load_index()
        if tid in idx:
            idx[tid].updated_at = msg.ts
            idx[tid].msg_count += 1
            self._save_index(idx)

    def read_msgs(self, tid: str, limit: int = 200) -> List[Msg]:
        p = self._thread_file(tid)
        if not p.exists(): return []
        msgs: List[Msg] = []
        for ln in p.read_text(encoding="utf-8").splitlines()[-limit:]:
            try:
                row = json.loads(ln)
                msgs.append(Msg(**row))
            except Exception:
                pass
        return msgs

    # plan cache per thread
    def save_plan(self, tid: str, plan: Dict[str, Any]) -> Path:
        fp = self._plan_file(tid)
        fp.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        return fp

    def load_plan(self, tid: str) -> Optional[Dict[str, Any]]:
        fp = self._plan_file(tid)
        if not fp.exists(): return None
        return json.loads(fp.read_text(encoding="utf-8"))
