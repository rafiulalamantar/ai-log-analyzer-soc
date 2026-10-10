"""Request and response schemas.

The LLM is instructed to emit `Analysis` as JSON; validating it here is what
turns a prose answer into data the dashboard, n8n and the eval harness can all
consume.
"""
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


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


class AnalyzeRequest(BaseModel):
    log: str = Field(..., min_length=1, description="Raw log text, one or more lines")
    source: Optional[str] = Field(
        None, description="Optional hint, e.g. 'auth.log', 'cloudtrail'"
    )


class AnalyzeResponse(BaseModel):
    # Kept so the contract documented in the report (§4.1) still holds.
    response: str
    analysis: Analysis
    model: str
    prompt_version: str
    latency_ms: int
