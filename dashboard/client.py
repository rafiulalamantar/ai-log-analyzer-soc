"""Everything the dashboard does that is not drawing: HTTP calls to the API,
the labelled corpus, and scoring a result against its label.

Kept free of Streamlit so it can be tested without a browser or a server. The
dashboard talks to the API over HTTP rather than importing `app`, so it shows
exactly what any other client would get.
"""
import json
import os
from dataclasses import dataclass
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_API = os.getenv("SOC_API", "http://localhost:8000")
# A full analysis is ~15s warm, and the first call after startup also loads the
# model, which can take a minute on its own.
ANALYZE_TIMEOUT = 180.0

SEVERITY_COLOR = {
    "info": "gray",
    "low": "blue",
    "medium": "orange",
    "high": "red",
    "critical": "violet",
}
# What a rules-only result means as a verdict; mirrors scripts/evaluate.py.
VERDICT_FOR_FLOOR = {
    "critical": "malicious",
    "high": "malicious",
    "medium": "suspicious",
    "low": "suspicious",
    "info": "benign",
}
VERDICT_ICON = {"benign": "✅", "suspicious": "⚠️", "malicious": "🚨"}


class ApiError(Exception):
    """A failure worth showing to the analyst as-is."""


def _client(base: str, timeout: float, transport: httpx.BaseTransport | None) -> httpx.Client:
    return httpx.Client(base_url=base, timeout=timeout, transport=transport)


def _detail(response: httpx.Response) -> str:
    try:
        return str(response.json().get("detail", response.text))
    except (json.JSONDecodeError, AttributeError):
        return response.text


def _post(base: str, path: str, body: dict, timeout: float, transport) -> dict:
    try:
        with _client(base, timeout, transport) as c:
            r = c.post(path, json=body)
    except httpx.TimeoutException as exc:
        raise ApiError(f"The API did not answer within {timeout:.0f}s.") from exc
    except httpx.HTTPError as exc:
        raise ApiError(f"Cannot reach the API at {base}. Is uvicorn running?") from exc

    if r.status_code == 503:
        raise ApiError(f"The AI engine is unavailable: {_detail(r)}")
    if r.status_code == 502:
        raise ApiError("The model returned an analysis that failed validation. "
                       "Try again; the rule results are unaffected.")
    if r.status_code >= 400:
        raise ApiError(f"HTTP {r.status_code}: {_detail(r)}")
    return r.json()


def health(base: str = DEFAULT_API, transport=None) -> dict:
    """/healthz, flattened to {status, ...}; never raises."""
    try:
        with _client(base, 5.0, transport) as c:
            r = c.get("/healthz")
    except httpx.HTTPError:
        return {"status": "api_down"}
    if r.status_code == 503:
        return {"status": "ollama_down", "detail": _detail(r)}
    if r.status_code != 200:
        return {"status": "error", "detail": f"HTTP {r.status_code}"}
    return r.json()


def prefilter(log: str, base: str = DEFAULT_API, transport=None) -> dict:
    return _post(base, "/prefilter", {"log": log}, 10.0, transport)


def analyze(log: str, source: str | None, base: str = DEFAULT_API, transport=None) -> dict:
    return _post(base, "/analyze", {"log": log, "source": source}, ANALYZE_TIMEOUT, transport)


@dataclass(frozen=True)
class Sample:
    dataset: str
    name: str
    path: Path
    label: dict | None

    @property
    def title(self) -> str:
        return f"{self.dataset}/{self.name}"


def samples(root: Path = ROOT) -> list[Sample]:
    """Every log in the dev and held-out corpora, with its label if it has one."""
    out = []
    for dataset in ("samples", "holdout"):
        folder = root / "data" / dataset
        labels_file = folder / "labels.json"
        labels = json.loads(labels_file.read_text()) if labels_file.exists() else {}
        for path in sorted(folder.glob("*.log")):
            out.append(Sample(dataset, path.name, path, labels.get(path.name)))
    return out


def against_label(label: dict, verdict: str, severity: str, technique: str | None) -> dict:
    """Same scoring as scripts/evaluate.py, so the dashboard and the report agree."""
    expected = label["mitre_any_of"]
    return {
        "verdict": verdict == label["verdict"],
        "severity": severity == label["severity"],
        "technique": (technique in expected) if expected else (technique is None),
    }


def attack_url(technique_id: str) -> str:
    """T1110.003 -> https://attack.mitre.org/techniques/T1110/003/"""
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"
