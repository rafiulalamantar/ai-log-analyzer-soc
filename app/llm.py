"""Ollama client: builds the prompt, calls the local model, validates the JSON."""
import json
import time

import httpx
from pydantic import ValidationError

from .config import settings
from .models import Analysis


class LLMUnavailable(RuntimeError):
    """Ollama could not be reached or did not answer in time."""


class LLMBadOutput(RuntimeError):
    """Ollama answered, but not with the schema we asked for."""


def build_prompt(log: str, source: str | None) -> str:
    template = settings.prompt_path.read_text(encoding="utf-8")
    return template.replace("{log}", log[: settings.max_log_chars]).replace(
        "{source}", source or "unspecified"
    )


async def analyze(log: str, source: str | None = None) -> tuple[Analysis, int]:
    """Return the validated analysis and the round-trip latency in ms."""
    payload = {
        "model": settings.ollama_model,
        "prompt": build_prompt(log, source),
        "stream": False,
        # Ollama constrains decoding to valid JSON; it does not enforce our
        # schema, so we still validate below.
        "format": "json",
        "options": {"temperature": 0.1},
    }

    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
            reply = await client.post(
                f"{settings.ollama_host}/api/generate", json=payload
            )
            reply.raise_for_status()
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        raise LLMUnavailable(str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        raise LLMUnavailable(
            f"ollama returned {exc.response.status_code}: {exc.response.text[:200]}"
        ) from exc
    latency_ms = int((time.perf_counter() - started) * 1000)

    raw = reply.json().get("response", "")
    try:
        return Analysis.model_validate(json.loads(raw)), latency_ms
    except (json.JSONDecodeError, ValidationError) as exc:
        raise LLMBadOutput(f"{exc}\n--- model said ---\n{raw[:500]}") from exc


async def ping() -> list[str]:
    """Names of the models Ollama currently has loaded. Raises if unreachable."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            reply = await client.get(f"{settings.ollama_host}/api/tags")
            reply.raise_for_status()
    except (httpx.HTTPError, httpx.TimeoutException) as exc:
        raise LLMUnavailable(str(exc)) from exc
    return [m.get("name", "") for m in reply.json().get("models", [])]
