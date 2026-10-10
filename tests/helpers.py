"""Shared test plumbing: drive app.llm's HTTP calls without a server."""
import asyncio
import json
from pathlib import Path

import httpx

from app import llm

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    """A recorded Ollama /api/generate response body."""
    return json.loads((FIXTURES / name).read_text())


def transport_for(monkeypatch, handler) -> None:
    """Route llm's HTTP calls through a MockTransport running `handler`."""
    def factory(**kwargs):
        kwargs.pop("timeout", None)
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(llm, "_http_client", factory)


def respond(payload: dict, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=payload)

    return handler


def fails_with(exc_type, message: str = "boom"):
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc_type(message, request=request)

    return handler


def run(coro):
    return asyncio.run(coro)
