from __future__ import annotations

import logging
from typing import Optional

import httpx

from .base import BaseIntegration, ConnectionResult

log = logging.getLogger(__name__)


class OllamaIntegration(BaseIntegration):
    """Thin client over Ollama's OpenAI-compatible `/v1/chat/completions` API.

    Works against:
      * Vanilla Ollama:       http://<host>:11434/v1
      * OpenWebUI proxy:      http://<host>:<port>/ollama/v1 or similar

    We prefer the OpenAI-compatible endpoint over native Ollama /api/generate
    because it lets us swap providers later (LM Studio, vLLM, etc.) without
    touching call sites.
    """

    name = "ollama"

    def __init__(
        self,
        host: str,
        port: int = 11434,
        model: str = "gemma3:4b",
        api_key: str = "",
        timeout: float = 300.0,
    ):
        self._host = host
        self._port = port
        self._model = model
        self._api_key = api_key
        self._timeout = timeout

    @property
    def _base_url(self) -> str:
        host = self._host.rstrip("/")
        # If caller gave us a full URL (e.g. http://host:port/ollama), respect it.
        if host.startswith("http://") or host.startswith("https://"):
            return host.rstrip("/")
        return f"http://{host}:{self._port}"

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    async def test_connection(self) -> ConnectionResult:
        """Pings /v1/models. Returns model list in detail on success."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    f"{self._base_url}/v1/models", headers=self._headers()
                )
                r.raise_for_status()
                data = r.json()
            models = [m.get("id", "?") for m in data.get("data", [])]
            has_target = self._model in models
            msg = f"Ollama reachable — {len(models)} model(s) available"
            if not has_target and models:
                msg += f"; configured model '{self._model}' NOT in list"
            return ConnectionResult.success(
                msg, models=models, model_present=has_target
            )
        except httpx.HTTPStatusError as e:
            return ConnectionResult.offline(
                f"HTTP {e.response.status_code}: {e.response.text[:200]}"
            )
        except Exception as e:
            return ConnectionResult.offline(self._safe_error(e))

    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Single-shot chat completion. Returns assistant text."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body: dict = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
            "stream": False,
        }
        if max_tokens is not None:
            body["max_tokens"] = max_tokens

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.post(
                f"{self._base_url}/v1/chat/completions",
                headers=self._headers(),
                json=body,
            )
            r.raise_for_status()
            data = r.json()

        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            log.warning("Unexpected Ollama response shape: %s", data)
            raise RuntimeError(f"Ollama returned no content: {e}") from e

    async def list_models(self) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    f"{self._base_url}/v1/models", headers=self._headers()
                )
                r.raise_for_status()
                return [m.get("id", "") for m in r.json().get("data", [])]
        except Exception as e:
            log.debug("list_models failed: %s", e)
            return []
