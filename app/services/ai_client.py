# app/services/ai_client.py
from __future__ import annotations
import os, json, urllib.request, urllib.error

class AIClient:
    """
    Minimal client:
      - Ollama: http://localhost:11434 (default), model via AI_MODEL (default 'llama3.1:8b')
      - OpenAI (opsional): set AI_PROVIDER=openai + OPENAI_API_KEY + AI_MODEL
    """
    def __init__(self):
        self.provider = os.environ.get("AI_PROVIDER", "ollama").strip().lower()
        self.model = os.environ.get("AI_MODEL", "llama3.1:8b")
        self.ollama_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        self.openai_key = os.environ.get("OPENAI_API_KEY")

    def generate(self, prompt: str, temperature: float = 0.2, max_tokens: int = 1024) -> str:
        return self._openai_chat(prompt, temperature, max_tokens) if self.provider == "openai" else self._ollama_generate(prompt, temperature)

    def _ollama_generate(self, prompt: str, temperature: float) -> str:
        url = f"{self.ollama_host}/api/generate"
        body = {"model": self.model, "prompt": prompt, "stream": False, "options": {"temperature": temperature},"format": "json", "num_ctx": 2048}
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type":"application/json"})
        try:
            with urllib.request.urlopen(req, timeout=240) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "").strip()
        except urllib.error.URLError as e:
            return f"[AI error: ollama connection failed: {e}]"

    def _openai_chat(self, prompt: str, temperature: float, max_tokens: int) -> str:
        if not self.openai_key:
            return "[AI error: OPENAI_API_KEY is not set]"
        url = "https://api.openai.com/v1/chat/completions"
        body = {
            "model": self.model,
            "messages": [
                {"role":"system","content":"You are a security testing assistant. Be concise."},
                {"role":"user","content": prompt}
            ],
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        headers = {"Content-Type":"application/json","Authorization": f"Bearer {self.openai_key}"}
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return (data.get("choices") or [{}])[0].get("message",{}).get("content","").strip()
        except urllib.error.URLError as e:
            return f"[AI error: openai connection failed: {e}]"
