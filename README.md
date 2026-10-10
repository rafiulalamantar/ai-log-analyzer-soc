# AI-Powered Incident Response and Security Log Analysis System

Local-first SOC log analysis: raw log text in, a structured threat assessment out.
Inference runs on your own machine via Ollama, so log data never leaves the host.

Implements Phases 1–2 of the build plan (FastAPI + Ollama core, structured output).
See the project report (`1791647043721_AI.docx`) for the full design.

## Status

| Component | State |
|---|---|
| FastAPI backend (`/`, `/healthz`, `/analyze`) | done |
| Ollama / Llama 3.1 integration | done |
| Structured JSON assessment (severity, MITRE, IOCs) | done |
| MITRE catalogue (constrains prompt, repairs output) | done |
| Sample log corpus | 3 files + `labels.json` ground truth |
| Prompt evaluation harness | done (`scripts/compare_prompts.py`) |
| Test suite | 14 tests, runs without Ollama |
| Deterministic pre-filter | not started (Phase 3) |
| Streamlit dashboard | not started (Phase 4) |
| Evaluation harness | not started (Phase 5) |
| n8n workflow | not started (Phase 6) |

## Setup

Install Ollama and pull the model (one time). No Homebrew or sudo needed —
this installs into your own `~/Applications`:

```bash
curl -L -o /tmp/Ollama-darwin.zip https://ollama.com/download/Ollama-darwin.zip
unzip -q /tmp/Ollama-darwin.zip -d ~/Applications/
ln -sf ~/Applications/Ollama.app/Contents/Resources/ollama ~/.local/bin/ollama
```

Then start the server and pull the model:

```bash
ollama serve &          # leave running
ollama pull llama3.1:8b
```

> Homebrew is not a usable route on this machine: `/opt/homebrew` is owned by a
> different user account, and brew does not support macOS 27. The zip above is
> the official signed build (Developer ID: Infra Technologies, Inc, 3MU9H2V9Y9).

Install Python dependencies:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env    # adjust if your Ollama host or model differs
```

## Run

```bash
.venv/bin/uvicorn app.main:app --reload
```

- Interactive API docs: http://localhost:8000/docs
- Readiness (checks Ollama *and* that the model is pulled): http://localhost:8000/healthz

## Analyze a log

```bash
curl -X POST http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"log": "Failed password for invalid user admin from 102.54.12.21", "source": "auth.log"}'
```

Or run a whole sample file through it:

```bash
scripts/smoke.sh data/samples/auth_brute_force.log
```

Response shape:

```json
{
  "response": "Repeated failed SSH logins from a single source IP...",
  "analysis": {
    "verdict": "malicious",
    "severity": "high",
    "attack_type": "SSH brute force",
    "confidence": 0.9,
    "mitre": {"technique_id": "T1110", "technique_name": "Brute Force"},
    "indicators": {"ips": ["102.54.12.21"], "users": ["admin", "root"], "hosts": [], "processes": [], "files": []},
    "summary": "...",
    "recommendations": ["Block 102.54.12.21 at the perimeter."],
    "supporting_lines": ["Failed password for invalid user admin..."]
  },
  "model": "llama3.1:8b",
  "prompt_version": "analyze_v1",
  "latency_ms": 4120
}
```

`response` is kept as a plain-text field so the API contract documented in the
report (§4.1) still holds; `analysis` is the structured form that the dashboard,
n8n and the evaluation harness all consume.

## Test

```bash
.venv/bin/python -m pytest tests/ -q
```

The LLM is stubbed, so the suite needs neither Ollama nor a network.

## Layout

```
app/
  main.py              FastAPI routes
  llm.py               Ollama client; validates the model's JSON
  models.py            request/response + Analysis schema
  config.py            environment-driven settings
  mitre.py             curated ATT&CK catalogue for log analysis
  prompts/
    analyze_v1.txt     v1: plain instructions (kept for comparison)
    analyze_v2.txt     v2: escalation rules + few-shot (default)
dashboard/             Streamlit UI (Phase 4)
data/samples/          log corpus + labels.json ground truth
data/eval/             evaluation output
scripts/compare_prompts.py   scores prompt versions against the labels
scripts/smoke.sh       end-to-end check against a running API
tests/test_api.py
```

## Evaluation

```bash
.venv/bin/python scripts/compare_prompts.py analyze_v1 analyze_v2
```

Scores each prompt version's verdict, severity and ATT&CK technique against
`data/samples/labels.json` and writes `data/eval/prompt_comparison.md`.

Measured on llama3.1:8b:

| prompt | fields correct | mean latency |
|---|---|---|
| analyze_v1 | 3 / 9 | 18.1 s |
| analyze_v2 | 9 / 9 | 20.2 s |

v1 under-called both attacks as `suspicious/medium` and labelled each of them
`T1210`. v2 adds explicit escalation rules (a success after repeated failures
is a *successful* breach; `curl | sh` is RCE; a UID 0 account is critical),
three worked examples, and a closed list of techniques to choose from.

**Caveat for anyone reading these numbers:** the corpus is three files and the
v2 examples resemble them, so this measures that the escalation rules fire, not
that the system generalises. A held-out set of logs the prompt was not written
against is needed before the figure means anything. Latency is unchanged in
practice — the larger prompt costs ~2 s.

## Notes

- The prompt is versioned on disk and echoed in every response, so results stay
  traceable to the prompt that produced them — needed for the Phase 5 evaluation.
- Technique *names* are looked up in `app/mitre.py`, never taken from the model,
  and an ID outside the catalogue is dropped rather than shown: a wrong
  technique misleads an analyst more than a missing one does.
- Ollama is asked for `format: "json"`, which constrains decoding to valid JSON
  but does not enforce our schema; `app/llm.py` validates against `Analysis` and
  returns HTTP 502 on a mismatch rather than passing junk downstream.
- First request after startup is slow (model load). Subsequent ones are faster.
- Every log line currently reaches the model. That is fine for a demo and will
  not hold at volume — Phase 3's pre-filter is what fixes it.
