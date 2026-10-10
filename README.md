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
| Deterministic pre-filter (8 rules, severity floor) | done |
| Sample log corpus | 6 files + `labels.json` ground truth |
| Evaluation harness | done (`scripts/evaluate.py`) |
| Test suite | 51 tests, runs without Ollama |
| Streamlit dashboard | not started (Phase 4) |
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

29 tests, no Ollama and no network required — verify that claim with:

```bash
OLLAMA_HOST=http://localhost:9 .venv/bin/python -m pytest tests/ -q
```

Two layers of coverage:

- The `/analyze` route tests replace `llm.analyze` outright, covering request
  validation and the 503/502 error paths.
- `tests/test_llm.py` drives the **real** `llm.analyze` through
  `httpx.MockTransport` with recorded Ollama response bodies in
  `tests/fixtures/`, so the parse -> validate -> `mitre.normalize` chain is
  covered without a server. That includes the observed failure modes: prose
  instead of JSON, a schema violation, an invented technique ID, and a
  technique name the catalogue has to correct.

What the suite does *not* measure is model accuracy — it never consults the
model. That is what `scripts/compare_prompts.py` is for.

## Layout

```
app/
  main.py              FastAPI routes
  llm.py               Ollama client; validates the model's JSON
  models.py            request/response + Analysis schema
  config.py            environment-driven settings
  mitre.py             curated ATT&CK catalogue for log analysis
  prefilter.py         deterministic rules + severity floor
  prompts/
    analyze_v1.txt     v1: plain instructions (kept for comparison)
    analyze_v2.txt     v2: escalation rules + few-shot (default)
dashboard/             Streamlit UI (Phase 4)
data/samples/          log corpus + labels.json ground truth
data/eval/             evaluation output
scripts/evaluate.py    scores rules / model / combined against the labels
scripts/smoke.sh       end-to-end check against a running API
tests/
  helpers.py           MockTransport plumbing shared by the test modules
  fixtures/            recorded Ollama response bodies
  test_api.py          routes, including /healthz
  test_llm.py          the real Ollama call path
  test_mitre.py        catalogue lookup and repair
  test_prefilter.py    every rule, both directions
```

## Evaluation

```bash
.venv/bin/python scripts/evaluate.py
```

Scores four configurations against `data/samples/labels.json` (6 labelled
samples x verdict, severity, technique = 18 fields) and writes
`data/eval/results.md`. Measured on llama3.1:8b:

| configuration | verdict | severity | technique | total | mean latency |
|---|---|---|---|---|---|
| rules only | 6/6 | 6/6 | 6/6 | **18/18** | <1ms |
| analyze_v1 | 3/6 | 3/6 | 3/6 | **9/18** | 20.1s |
| analyze_v2 | 5/6 | 5/6 | 5/6 | **15/18** | 20.6s |
| analyze_v2 + rules | 5/6 | 5/6 | 5/6 | **15/18** | 20.6s |

Three findings worth reading before trusting any of this:

**The deterministic layer beats the model outright, by four orders of magnitude
less compute.** That is not an argument for deleting the LLM — the rules only
catch what they were taught, and 8 rules cannot cover a SOC. It *is* an argument
for running them first and treating the model as the thing that handles what the
rules do not recognise.

**v2's single failure is a false positive, not a miss.** It calls
`user_typo.log` — two mistyped passwords then a success from an internal host —
`malicious/critical`. The escalation rules that fixed v1's under-calling taught
it "failures then success = breach" with no notion of a threshold, so it now
over-reports. v1 got that sample right by being wrong everywhere else. Swapping
a false negative for a false positive is not progress; an analyst who gets paged
for typos stops reading the pages.

**The severity floor adds nothing on this corpus**, because the floor only
raises an assessment and the one defect needs lowering. It stays in because it
protects against the v1 failure mode, which is the one that lets a real breach
through — but the honest reading is that it is insurance, not an improvement.
A ceiling (capping the model when no rule fired) would fix `user_typo.log`,
at the cost of letting the rules veto a novel threat the model spotted. That
trade is not obviously worth making.

**Caveat on all of it:** six samples, written by the same person who wrote the
rules and the prompt. The rules' 18/18 partly measures that the rules were
written against these files. A held-out set is needed before any of these
numbers belong in a report as an accuracy claim.

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
