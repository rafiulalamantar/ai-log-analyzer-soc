"""FastAPI service for AI-powered security log analysis."""
import logging

from fastapi import FastAPI, HTTPException

from . import llm, prefilter
from .config import settings
from .models import AnalyzeRequest, AnalyzeResponse, PrefilterReport

log = logging.getLogger("soc")

app = FastAPI(
    title="AI-Powered Incident Response and Security Log Analysis System",
    version="0.1.0",
)


@app.get("/")
async def root() -> dict:
    """Health check, as documented in the project report."""
    return {"status": "running"}


@app.get("/healthz")
async def healthz() -> dict:
    """Readiness: is Ollama up, and is the configured model actually pulled?"""
    try:
        available = await llm.ping()
    except llm.LLMUnavailable as exc:
        raise HTTPException(
            status_code=503, detail=f"ollama unreachable at {settings.ollama_host}: {exc}"
        ) from exc

    model_ready = any(m.startswith(settings.ollama_model.split(":")[0]) for m in available)
    return {
        "status": "ready" if model_ready else "model_missing",
        "configured_model": settings.ollama_model,
        "available_models": available,
        "prompt_version": settings.prompt_version,
    }


@app.post("/prefilter", response_model=PrefilterReport)
async def prefilter_only(request: AnalyzeRequest) -> PrefilterReport:
    """Run the deterministic rules alone: no model, microseconds, no GPU.

    Useful for triaging volume before deciding what deserves an LLM call.
    """
    return prefilter.run(request.log)


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze raw log text: deterministic rules first, then the model."""
    report = prefilter.run(request.log)
    try:
        analysis, latency_ms = await llm.analyze(request.log, request.source)
    except llm.LLMUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"AI engine unavailable: {exc}") from exc
    except llm.LLMBadOutput as exc:
        log.warning("schema violation from model: %s", exc)
        raise HTTPException(
            status_code=502, detail="AI engine returned malformed analysis"
        ) from exc

    # Rules override the model upward, never downward.
    report.applied_floor = prefilter.apply_floor(analysis, report)

    return AnalyzeResponse(
        response=analysis.summary,
        analysis=analysis,
        prefilter=report,
        model=settings.ollama_model,
        prompt_version=settings.prompt_version,
        latency_ms=latency_ms,
    )
