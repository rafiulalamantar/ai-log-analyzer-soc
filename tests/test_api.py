"""API tests. The LLM is stubbed so the suite runs without Ollama."""
import pytest
from fastapi.testclient import TestClient

import httpx

from app import llm
from app.main import app
from app.models import Analysis

from .helpers import fails_with, respond, transport_for

client = TestClient(app)

STUB = Analysis.model_validate(
    {
        "verdict": "malicious",
        "severity": "high",
        "attack_type": "SSH brute force",
        "confidence": 0.9,
        "mitre": {"technique_id": "T1110", "technique_name": "Brute Force"},
        "indicators": {"ips": ["102.54.12.21"], "users": ["admin", "root"]},
        "summary": "Repeated failed SSH logins from a single source IP.",
        "recommendations": ["Block 102.54.12.21 at the perimeter."],
        "supporting_lines": ["Failed password for invalid user admin"],
    }
)


def test_root_matches_documented_contract():
    assert client.get("/").json() == {"status": "running"}


def test_analyze_returns_structured_assessment(monkeypatch):
    async def fake(log, source=None):
        return STUB, 1234

    monkeypatch.setattr(llm, "analyze", fake)
    body = client.post("/analyze", json={"log": "Failed password for admin"}).json()

    assert body["analysis"]["severity"] == "high"
    assert body["analysis"]["mitre"]["technique_id"] == "T1110"
    assert body["latency_ms"] == 1234
    # Prose contract from the report is preserved alongside the structure.
    assert body["response"] == STUB.summary


def test_empty_log_is_rejected():
    assert client.post("/analyze", json={"log": ""}).status_code == 422


def test_unreachable_engine_returns_503(monkeypatch):
    async def boom(log, source=None):
        raise llm.LLMUnavailable("connection refused")

    monkeypatch.setattr(llm, "analyze", boom)
    assert client.post("/analyze", json={"log": "x"}).status_code == 503


def test_malformed_model_output_returns_502(monkeypatch):
    async def bad(log, source=None):
        raise llm.LLMBadOutput("not json")

    monkeypatch.setattr(llm, "analyze", bad)
    assert client.post("/analyze", json={"log": "x"}).status_code == 502


def test_prompt_includes_log_and_source():
    prompt = llm.build_prompt("Failed password for root", "auth.log")
    assert "Failed password for root" in prompt
    assert "auth.log" in prompt
    assert "{log}" not in prompt


# --- /healthz: the one route that always talks to Ollama --------------------

def test_healthz_ready_when_model_is_pulled(monkeypatch):
    transport_for(monkeypatch, respond({"models": [{"name": "llama3.1:8b"}]}))
    body = client.get("/healthz").json()

    assert body["status"] == "ready"
    assert body["available_models"] == ["llama3.1:8b"]
    assert body["prompt_version"] == "analyze_v2"


def test_healthz_reports_model_missing_when_nothing_pulled(monkeypatch):
    # Ollama is up but empty: a real state, and not the same as being down.
    transport_for(monkeypatch, respond({"models": []}))
    body = client.get("/healthz").json()

    assert body["status"] == "model_missing"
    assert body["available_models"] == []


def test_healthz_returns_503_when_ollama_is_down(monkeypatch):
    transport_for(monkeypatch, fails_with(httpx.ConnectError, "connection refused"))
    response = client.get("/healthz")

    assert response.status_code == 503
    assert "unreachable" in response.json()["detail"]
