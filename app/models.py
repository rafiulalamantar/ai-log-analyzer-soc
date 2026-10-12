"""Request and response schemas.

The LLM is instructed to emit `Analysis` as JSON; validating it here is what
turns a prose answer into data the dashboard, n8n and the eval harness can all
consume.
"""
import json
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


def _as_lines(value):
    """Coerce list items back to strings.

    Asked to quote lines verbatim from a JSON log (CloudTrail, Zeek, any
    structured source), the model returns them as objects rather than strings.
    Rejecting that discards an otherwise correct assessment over formatting, so
    re-serialize instead.
    """
    if not isinstance(value, list):
        return value
    return [
        item if isinstance(item, str) else json.dumps(item, separators=(",", ":"))
        for item in value
    ]


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Verdict(str, Enum):
    benign = "benign"
    suspicious = "suspicious"
    malicious = "malicious"


class Mitre(BaseModel):
    technique_id: Optional[str] = Field(None, description="e.g. T1110")
    technique_name: Optional[str] = None


class Indicators(BaseModel):
    ips: list[str] = []
    users: list[str] = []
    hosts: list[str] = []
    processes: list[str] = []
    files: list[str] = []

    _coerce = field_validator("ips", "users", "hosts", "processes", "files", mode="before")(
        _as_lines
    )


class Signal(BaseModel):
    """One deterministic rule hit. No model involved."""

    rule_id: str
    name: str
    severity: Severity
    technique_id: Optional[str] = None
    detail: str
    lines: list[str] = []


class PrefilterReport(BaseModel):
    """What the rule layer concluded before the model was consulted."""

    events_parsed: int
    signals: list[Signal] = []
    severity_floor: Severity = Severity.info
    clean: bool = True
    applied_floor: bool = Field(
        False, description="True if the rules raised the model's own assessment"
    )


class Analysis(BaseModel):
    """The structured verdict the model must return."""

    verdict: Verdict
    severity: Severity
    attack_type: str = Field(..., description="Short label, e.g. 'SSH brute force'")
    confidence: float = Field(..., ge=0.0, le=1.0)
    mitre: Mitre = Mitre()
    indicators: Indicators = Indicators()
    summary: str
    recommendations: list[str] = []
    supporting_lines: list[str] = Field(
        default=[], description="Verbatim log lines that justify the verdict"
    )

    _coerce_lines = field_validator("supporting_lines", mode="before")(_as_lines)


class AnalyzeRequest(BaseModel):
    log: str = Field(..., min_length=1, description="Raw log text, one or more lines")
    source: Optional[str] = Field(
        None, description="Optional hint, e.g. 'auth.log', 'cloudtrail'"
    )


class AnalyzeResponse(BaseModel):
    # Kept so the contract documented in the report (§4.1) still holds.
    response: str
    analysis: Analysis
    prefilter: PrefilterReport
    model: str
    prompt_version: str
    latency_ms: int
