# app/services/llm_provider.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import hashlib
import json
import time
import requests


@dataclass
class LLMItem:
    url: str
    method: Optional[str] = None
    code: Optional[int] = None
    ctype: Optional[str] = None
    size: Optional[int] = None
    path: Optional[str] = None  # tail dari URL


@dataclass
class LLMLabel:
    url: str
    label: str          # HIGH | MEDIUM | LOW | INFO
    reason: str
    source: str = "llm" # penanda di UI


@dataclass
class ProviderHealth:
    ok: bool
    model: str
    detail: str = ""


class LLMProvider:
    """Interface. Implement minimal: classify_batch, health, name."""
    name: str

    def classify_batch(self, items: List[LLMItem]) -> List[LLMLabel]:
        raise NotImplementedError

    def health(self) -> ProviderHealth:
        raise NotImplementedError


class OllamaProvider(LLMProvider):
    """
    Penyambung ke Ollama (localhost:11434).
    Harus pakai 'format: json' supaya balasan bisa diparse deterministik.
    """
    def __init__(self, model: str = "llama3.1:8b", base_url: str = "http://localhost:11434", timeout: int = 30):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.name = f"ollama:{self.model}"

    def _prompt(self, items: List[LLMItem]) -> str:
        # Ringkas + ketat: minta skema JSON valid
        lines = []
        for it in items:
            # ambil konteks yang kecil agar cepat
            code = it.code if it.code is not None else "-"
            ctype = it.ctype or "-"
            size = it.size if it.size is not None else "-"
            path = it.path or "-"
            method = it.method or "-"
            lines.append(f'["{it.url}","{method}",{code},"{ctype}",{size},"{path}"]')

        urls_block = ",\n".join(lines)
        return (
            "You are a security triage assistant. Classify each URL with one of: "
            "HIGH, MEDIUM, LOW, INFO. Respond **valid JSON** only.\n"
            "A HIGH example: .git/config, /.env, /id_rsa, open Jenkins, unauthenticated DB consoles.\n"
            "MEDIUM example: /admin/ (unknown auth), /wp-admin/, default dashboards, upload/ dirs.\n"
            "LOW example: static images, css/js, harmless docs.\n"
            "INFO is for uninteresting.\n\n"
            "For each item, output: {\"url\":..., \"label\":\"HIGH|MEDIUM|LOW|INFO\", \"reason\":\"…\"}\n"
            "Input rows: [url, method, code, content_type, size, path_tail]. Consider code/ctype when relevant.\n\n"
            "{items:[\n"
            f"{urls_block}\n"
            "]}"
        )

    def classify_batch(self, items: List[LLMItem]) -> List[LLMLabel]:
        prompt = self._prompt(items)
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",  # <-- minta JSON valid
            "options": {
                "temperature": 0.2,
            },
        }
        url = f"{self.base_url}/api/generate"
        t0 = time.time()
        r = requests.post(url, json=payload, timeout=self.timeout)
        dt = time.time() - t0
        r.raise_for_status()
        data = r.json()
        # Ollama balikin {response: "...json..."} saat format=json -> response sudah object/dict
        obj = data.get("response", {})
        if isinstance(obj, str):
            # fallback kalau masih string
            obj = json.loads(obj)

        out: List[LLMLabel] = []
        for it in (obj.get("items") or []):
            url_s = it.get("url") or ""
            label = (it.get("label") or "INFO").upper()
            reason = it.get("reason") or "-"
            if label not in ("HIGH", "MEDIUM", "LOW", "INFO"):
                label = "INFO"
            out.append(LLMLabel(url=url_s, label=label, reason=reason, source="llm"))
        # Bisa log dt untuk telemetry kalau mau
        return out

    def health(self) -> ProviderHealth:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=3)
            ok = r.status_code == 200
            return ProviderHealth(ok=ok, model=self.model, detail="ok" if ok else f"status={r.status_code}")
        except Exception as e:
            return ProviderHealth(ok=False, model=self.model, detail=str(e))
