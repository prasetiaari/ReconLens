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

# OpenAI provider implementation
class OpenAIProvider(LLMProvider):
    """Provider that uses OpenAI API (or compatible) for classification."""
    def __init__(self, model: str = "gpt-3.5-turbo", endpoint: str = "https://api.openai.com/v1/chat/completions", api_key: str = "", timeout: int = 30):
        self.model = model
        self.endpoint = endpoint.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.name = f"openai:{self.model}"

    def _prompt(self, items: List[LLMItem]) -> str:
        # Reuse the same prompt format as OllamaProvider for consistency
        lines = []
        for it in items:
            code = it.code if it.code is not None else "-"
            ctype = it.ctype or "-"
            size = it.size if it.size is not None else "-"
            path = it.path or "-"
            method = it.method or "-"
            lines.append(f'["{it.url}","{method}",{code},"{ctype}",{size},"{path}"]')
        urls_block = ",\n".join(lines)
        return (
            "You are a security triage assistant. Classify each URL with one of: HIGH, MEDIUM, LOW, INFO. Respond **valid JSON** only.\n"
            "A HIGH example: .git/config, /.env, /id_rsa, open Jenkins, unauthenticated DB consoles.\n"
            "MEDIUM example: /admin/ (unknown auth), /wp-admin/, default dashboards, upload/ dirs.\n"
            "LOW example: static images, css/js, harmless docs.\n"
            "INFO is for uninteresting.\n"
            "For each item, output: {\"url\":..., \"label\":\"HIGH|MEDIUM|LOW|INFO\", \"reason\":\"…\"}\n"
            "Input rows: [url, method, code, content_type, size, path_tail]. Consider code/ctype when relevant.\n"
            "{items:[\n" + f"{urls_block}" + "\n]}"
        )

    def classify_batch(self, items: List[LLMItem]) -> List[LLMLabel]:
        prompt = self._prompt(items)
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": prompt}],
            "temperature": 0.2,
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}" if self.api_key else "",
        }
        try:
            r = requests.post(self.endpoint, json=payload, headers=headers, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
            # OpenAI returns choices list with message content
            content = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
            obj = json.loads(content) if isinstance(content, str) else content
        except Exception as e:
            # Return empty list on error, could be logged
            return []
        out: List[LLMLabel] = []
        for it in (obj.get("items") or []):
            url_s = it.get("url") or ""
            label = (it.get("label") or "INFO").upper()
            reason = it.get("reason") or "-"
            if label not in ("HIGH", "MEDIUM", "LOW", "INFO"):
                label = "INFO"
            out.append(LLMLabel(url=url_s, label=label, reason=reason, source="llm"))
        return out

    def health(self) -> ProviderHealth:
        # Simple health check: try a tiny request
        try:
            payload = {"model": self.model, "messages": [{"role": "system", "content": "ping"}], "temperature": 0.0}
            headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}" if self.api_key else ""}
            r = requests.post(self.endpoint, json=payload, headers=headers, timeout=3)
            ok = r.status_code == 200
            return ProviderHealth(ok=ok, model=self.model, detail="ok" if ok else f"status={r.status_code}")
        except Exception as e:
            return ProviderHealth(ok=False, model=self.model, detail=str(e))

# Factory to select provider based on app settings
from ..config import Settings

from ..core.config_store import load_settings

def get_llm_provider(settings: Settings) -> LLMProvider:
    try:
        runtime_settings = load_settings()
        ai_cfg = runtime_settings.get("ai", {})
        source = ai_cfg.get("source") or settings.AI_MODEL_SOURCE or "local"
        model = ai_cfg.get("model") or settings.AI_MODEL_NAME or "llama3.1:8b"
        endpoint = ai_cfg.get("endpoint") or settings.AI_CLOUD_ENDPOINT or "https://api.openai.com/v1/chat/completions"
        api_key = ai_cfg.get("api_key") or settings.AI_CLOUD_API_KEY or ""
    except Exception:
        source = settings.AI_MODEL_SOURCE or "local"
        model = settings.AI_MODEL_NAME or "llama3.1:8b"
        endpoint = settings.AI_CLOUD_ENDPOINT or "https://api.openai.com/v1/chat/completions"
        api_key = settings.AI_CLOUD_API_KEY or ""

    source = source.strip().lower()
    if source == "cloud":
        return OpenAIProvider(
            model=model,
            endpoint=endpoint,
            api_key=api_key,
        )
    return OllamaProvider(model=model)
