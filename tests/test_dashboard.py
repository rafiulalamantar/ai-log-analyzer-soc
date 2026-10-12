"""Dashboard tests. The client is driven through the real FastAPI app (LLM
stubbed) so a drift between what the API returns and what the dashboard reads
fails here rather than in front of an analyst."""
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from streamlit.testing.v1 import AppTest

from app import llm
from app.main import app

from .test_api import STUB

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dashboard"))

import client  # noqa: E402

api = TestClient(app)
ROOT_LOG = "Oct  9 16:40:13 db02 useradd[7721]: new user: name=svc, UID=0, GID=0, home=/home/svc"


def via_app(request: httpx.Request) -> httpx.Response:
    """Forward a dashboard request to the in-process API."""
    r = api.request(request.method, request.url.path, content=request.content,
                    headers={"content-type": "application/json"})
    return httpx.Response(r.status_code, content=r.content, headers=r.headers)


APP = httpx.MockTransport(via_app)


def status(code: int, body: dict | None = None):
    return httpx.MockTransport(lambda request: httpx.Response(code, json=body or {}))


@pytest.fixture
def stub_model(monkeypatch):
    async def fake(log, source=None):
        return STUB.model_copy(deep=True), 100

    monkeypatch.setattr(llm, "analyze", fake)


# --- client against the real API ------------------------------------------

def test_prefilter_round_trip():
    report = client.prefilter(ROOT_LOG, transport=APP)
    assert report["severity_floor"] == "critical"
    assert report["signals"][0]["rule_id"] == "R005"


def test_analyze_round_trip(stub_model):
    body = client.analyze(ROOT_LOG, "auth.log", transport=APP)
    assert body["analysis"]["severity"] == "critical"  # floor applied
    assert body["prefilter"]["applied_floor"] is True


def test_health_when_ollama_down(monkeypatch):
    async def down():
        raise llm.LLMUnavailable("connection refused")

    monkeypatch.setattr(llm, "ping", down)
    assert client.health(transport=APP)["status"] == "ollama_down"


def test_every_severity_the_api_can_return_has_an_order_and_color():
    from app.models import Severity

    for s in Severity:
        assert s.value in client.SEVERITY_ORDER
        assert s.value in client.SEVERITY_COLOR
        assert s.value in client.VERDICT_FOR_FLOOR


# --- errors are turned into sentences --------------------------------------

def test_api_unreachable_is_reported():
    with pytest.raises(client.ApiError, match="Is uvicorn running"):
        client.prefilter("x", transport=httpx.MockTransport(
            lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused", request=r))))
    assert client.health(transport=httpx.MockTransport(
        lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused", request=r))))["status"] == "api_down"


@pytest.mark.parametrize("code,text", [(503, "unavailable"), (502, "failed validation"), (422, "HTTP 422")])
def test_http_errors_become_api_errors(code, text):
    with pytest.raises(client.ApiError, match=text):
        client.analyze("x", None, transport=status(code, {"detail": "nope"}))


# --- corpus and scoring ----------------------------------------------------

def test_samples_cover_both_corpora_with_labels():
    found = client.samples()
    assert {s.dataset for s in found} == {"samples", "holdout"}
    assert all(s.label is not None for s in found)


def test_against_label_matches_evaluate_semantics():
    label = {"verdict": "benign", "severity": "info", "mitre_any_of": []}
    assert client.against_label(label, "benign", "info", None) == {
        "verdict": True, "severity": True, "technique": True}
    assert client.against_label(label, "benign", "info", "T1110")["technique"] is False


def test_attack_url_handles_subtechniques():
    assert client.attack_url("T1110.003") == "https://attack.mitre.org/techniques/T1110/003/"
    assert client.attack_url("T1078") == "https://attack.mitre.org/techniques/T1078/"


# --- the Streamlit app itself ---------------------------------------------

@pytest.fixture
def dashboard(monkeypatch, stub_model):
    """The app with every HTTP call routed to the in-process API."""
    async def ready():
        return ["llama3.1:8b"]

    monkeypatch.setattr(llm, "ping", ready)
    real = client._client
    monkeypatch.setattr(client, "_client", lambda base, timeout, transport: real(base, timeout, APP))
    at = AppTest.from_file(str(ROOT / "dashboard" / "app.py"), default_timeout=30)
    return at.run()


def test_app_loads_and_sees_a_ready_engine(dashboard):
    assert not dashboard.exception
    assert "Ready" in dashboard.sidebar.success[0].value


def test_app_rules_only_on_a_corpus_sample(dashboard):
    dashboard.selectbox[0].select("samples/privilege_escalation.log").run()
    next(b for b in dashboard.button if b.label == "Rules only").click().run()
    assert not dashboard.exception
    assert any(t.value == "Rule layer" for t in dashboard.subheader)
    assert any(t.value == "Against the label" for t in dashboard.subheader)


def test_app_full_analysis(dashboard):
    next(b for b in dashboard.button if b.label == "Full analysis").click().run()
    assert not dashboard.exception
    assert any(t.value == STUB.attack_type for t in dashboard.subheader)


def test_app_rules_only_does_not_call_silence_benign(dashboard):
    dashboard.selectbox[0].select("samples/benign_noise.log").run()
    next(b for b in dashboard.button if b.label == "Rules only").click().run()
    assert dashboard.metric[0].value == "— no rule fired"
