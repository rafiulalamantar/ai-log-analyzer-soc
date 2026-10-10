"""The real llm.analyze path, driven by recorded Ollama response bodies.

The /analyze route tests stub llm.analyze outright, so the parse -> validate ->
mitre.normalize chain was previously only exercised by live runs against the
model. These tests close that gap with httpx.MockTransport: no server, no
network, but the production code path.
"""
import dataclasses
import json

import httpx
import pytest

from app import llm
from app.config import settings as base_settings

from .helpers import fails_with, load, respond, run, transport_for


# --- the happy path ---------------------------------------------------------

def test_recorded_response_parses_into_analysis(monkeypatch):
    transport_for(monkeypatch, respond(load("ollama_brute_force.json")))
    analysis, latency_ms = run(llm.analyze("Failed password for admin", "auth.log"))

    assert analysis.verdict.value == "malicious"
    assert analysis.severity.value == "critical"
    assert analysis.confidence == 0.9
    assert analysis.mitre.technique_id == "T1110"
    assert analysis.indicators.ips == ["102.54.12.21"]
    assert "deploy" in analysis.indicators.users
    assert latency_ms >= 0


def test_request_sent_to_ollama_is_well_formed(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=load("ollama_brute_force.json"))

    transport_for(monkeypatch, handler)
    run(llm.analyze("Failed password for root", "auth.log"))

    assert seen["url"].endswith("/api/generate")
    body = seen["body"]
    assert body["model"] == base_settings.ollama_model
    assert body["stream"] is False
    # JSON-constrained decoding is what keeps the parse step viable.
    assert body["format"] == "json"
    assert body["options"]["temperature"] == 0.1
    assert "Failed password for root" in body["prompt"]
    assert "auth.log" in body["prompt"]
    # The catalogue must reach the model, or it cannot pick from a closed list.
    assert "T1110  Brute Force" in body["prompt"]


def test_oversized_log_is_truncated_before_sending(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=load("ollama_brute_force.json"))

    transport_for(monkeypatch, handler)
    monkeypatch.setattr(llm, "settings", dataclasses.replace(base_settings, max_log_chars=50))
    run(llm.analyze("A" * 5000, None))

    assert "A" * 50 in seen["body"]["prompt"]
    assert "A" * 51 not in seen["body"]["prompt"]


# --- the MITRE repair chain, through the real call -------------------------

def test_invented_technique_is_dropped_not_passed_on(monkeypatch):
    transport_for(monkeypatch, respond(load("ollama_bad_technique.json")))
    analysis, _ = run(llm.analyze("x", None))

    # T9999 is not in the catalogue, so it must not reach an analyst.
    assert analysis.mitre.technique_id is None
    assert analysis.mitre.technique_name is None
    # The rest of the assessment survives the dropped technique.
    assert analysis.verdict.value == "malicious"


def test_technique_name_is_replaced_from_the_catalogue(monkeypatch):
    transport_for(monkeypatch, respond(load("ollama_wrong_technique_name.json")))
    analysis, _ = run(llm.analyze("x", None))

    assert analysis.mitre.technique_id == "T1210"
    assert analysis.mitre.technique_name == "Exploitation of Remote Services"


# --- failure modes ---------------------------------------------------------

def test_non_json_reply_raises_bad_output(monkeypatch):
    payload = {"model": "llama3.1:8b", "response": "Sure! Here is my analysis:", "done": True}
    transport_for(monkeypatch, respond(payload))
    with pytest.raises(llm.LLMBadOutput):
        run(llm.analyze("x", None))


def test_schema_violation_raises_bad_output(monkeypatch):
    # Valid JSON, but confidence is out of range and verdict is not in the enum.
    payload = {
        "model": "llama3.1:8b",
        "response": json.dumps({"verdict": "very bad", "severity": "critical", "confidence": 7}),
        "done": True,
    }
    transport_for(monkeypatch, respond(payload))
    with pytest.raises(llm.LLMBadOutput):
        run(llm.analyze("x", None))


def test_ollama_server_error_raises_unavailable(monkeypatch):
    transport_for(monkeypatch, respond({"error": "model requires more system memory"}, status=500))
    with pytest.raises(llm.LLMUnavailable):
        run(llm.analyze("x", None))


def test_connect_error_raises_unavailable(monkeypatch):
    transport_for(monkeypatch, fails_with(httpx.ConnectError, "connection refused"))
    with pytest.raises(llm.LLMUnavailable):
        run(llm.analyze("x", None))


def test_timeout_raises_unavailable(monkeypatch):
    transport_for(monkeypatch, fails_with(httpx.ReadTimeout, "took too long"))
    with pytest.raises(llm.LLMUnavailable):
        run(llm.analyze("x", None))


# --- readiness probe -------------------------------------------------------

def test_ping_lists_pulled_models(monkeypatch):
    transport_for(monkeypatch, respond({"models": [{"name": "llama3.1:8b"}, {"name": "phi3:mini"}]}))
    assert run(llm.ping()) == ["llama3.1:8b", "phi3:mini"]


def test_ping_on_dead_server_raises_unavailable(monkeypatch):
    transport_for(monkeypatch, fails_with(httpx.ConnectError, "nothing listening"))
    with pytest.raises(llm.LLMUnavailable):
        run(llm.ping())
