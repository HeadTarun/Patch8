"""Minimal provider clients using Python's standard HTTP library."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


def _post(url: str, payload: dict, headers: dict | None = None) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            return json.loads(response.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Model request failed: {exc}") from exc


def generate(provider: str, prompt: str) -> str:
    if provider == "hosted":
        key = os.getenv("OPENAI_API_KEY", "")
        if not key:
            raise RuntimeError("Hosted repair is not configured. Set OPENAI_API_KEY on the API service.")
        base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        data = _post(
            f"{base}/chat/completions",
            {
                "model": os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": "Return only JSON with keys file, code, explanation. Keep the repair minimal. Preserve behavior and public interfaces. Do not claim tests passed."},
                    {"role": "user", "content": prompt},
                ],
            },
            {"Authorization": f"Bearer {key}"},
        )
        return data["choices"][0]["message"]["content"]

    if provider == "ollama":
        base = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434").rstrip("/")
        data = _post(
            f"{base}/api/chat",
            {
                "model": os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b"),
                "stream": False,
                "format": "json",
                "messages": [
                    {"role": "system", "content": "Return only JSON with keys file, code, explanation. Keep the repair minimal. Preserve behavior and public interfaces. Do not claim tests passed."},
                    {"role": "user", "content": prompt},
                ],
            },
        )
        return data["message"]["content"]
    raise RuntimeError("Choose a supported repair provider.")
