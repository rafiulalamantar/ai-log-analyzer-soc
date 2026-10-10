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
| Log corpus | 6 dev + 29 held-out samples, labelled |
| Evaluation harness | done (`scripts/evaluate.py`) |
| Test suite | 75 tests, runs without Ollama |
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
data/samples/          dev corpus (detector written against these)
data/holdout/          held-out corpus, 29 labelled samples
data/eval/             evaluation output, per dataset
scripts/evaluate.py    scores rules / model / combined against the labels
scripts/smoke.sh       end-to-end check against a running API
tests/
  helpers.py           MockTransport plumbing shared by the test modules
  fixtures/            recorded Ollama response bodies
  test_api.py          routes, including /healthz
  test_llm.py          the real Ollama call path
  test_mitre.py        catalogue lookup and repair
  test_prefilter.py    every rule, both directions
  test_corpus.py       label integrity: unscoreable labels fail the build
```

## Evaluation

Two datasets, because a score on logs you wrote the detector against means
something different from a score on logs you did not:

| dataset | what it is |
|---|---|
| `data/samples/` | 6 samples. The rules and prompts were written against these. A high score here measures agreement, not skill. |
| `data/holdout/` | 29 samples (18 attack / 11 benign). Web, cloud, Windows, DNS, firewall and container logs the rules were never written for, plus 11 benign samples — 5 of them built as traps for specific rules. |

```bash
.venv/bin/python scripts/evaluate.py                                    # dev set
.venv/bin/python scripts/evaluate.py --dataset holdout --versions ""    # rules only, instant
.venv/bin/python scripts/evaluate.py --dataset holdout --versions analyze_v2
```

Precision and recall below are over attack-vs-benign — the decision an analyst
acts on. FP counts benign samples reported as an attack.

**Dev set** (6 samples):

| configuration | fields | precision | recall | FP | mean latency |
|---|---|---|---|---|---|
| rules | 18/18 | 1.00 | 1.00 | 0 | <1ms |
| analyze_v1 | 9/18 | 1.00 | 1.00 | 0 | 19.4s |
| analyze_v2 | 15/18 | 0.80 | 1.00 | 1 | 20.6s |
| analyze_v2 + rules | 15/18 | 0.80 | 1.00 | 1 | 20.6s |

**Held-out set** (29 samples):

| configuration | fields | precision | recall | FP | mean latency |
|---|---|---|---|---|---|
| rules | 45/87 | 1.00 | 0.28 | 0 | <1ms |
| analyze_v2 | 64/87 | 0.93 | 0.78 | 1 | 20.5s |
| analyze_v2 + rules | 64/87 | 0.93 | 0.78 | 1 | 20.5s |

### What the held-out set showed

**Detection and grading are different axes.** On the dev set `analyze_v1`
separates attack from benign perfectly (precision 1.00, recall 1.00) while
scoring only 9/18 on fields: it noticed every attack and graded all of them
wrong, calling a live breach `suspicious/medium`. Recall alone would have
called v1 finished.

**The dev-set result was overfitting, and the holdout measures how much.** The
rules score 18/18 with recall 1.00 on the files they were written against, and
recall 0.28 on files they were not. Any evaluation run only against
`data/samples/` should be read as a regression check, not as accuracy.

**The rules are a strict subset of the model.** Every attack the rules caught,
`analyze_v2` also caught: union recall is 0.78, identical to the model alone.
On unseen data the rule layer adds no detection coverage whatsoever. It still
earns its place for cost (sub-millisecond versus 20 seconds), for precision
(1.00 with zero false positives, against the model's 0.93), and because a rule
hit is auditable in a way a model verdict is not — but "rules catch what the
model misses" is not supported by this corpus, and the earlier dev-set claim
that they beat the model does not survive contact with held-out data.

**Four attacks evaded both layers:** cron persistence, cryptomining, container
escape via a mounted `docker.sock`, and a port scan. All four are outside the
rules' scope, and all four are cases where the log line looks mundane unless
you know the context (a hidden path under `/tmp`, a miner named `kworkerd`).

**One false positive, reproduced across both datasets.** `analyze_v2` pages on
`benign_failed_su.log` (holdout) and `user_typo.log` (dev) — in both, a user
fails authentication once or twice and then succeeds. Escalation rule 1 taught
the model "failures then success = breach" with no threshold, while the rules
layer uses a threshold of 3. Two independent samples with the same cause makes
this systematic, not noise, and it is the strongest argument for an
`analyze_v3` that teaches the prompt the same threshold the rules use.

**The rule layer has a brittleness defect, separate from its coverage gaps.**
`imap_brute_success.log` is the same attack as the dev corpus — repeated
failures then a success from one address — and R001 misses it because Dovecot
writes `auth failed ... rip=` where OpenSSH writes `Failed password for ... from`.
A rule that covers one vendor's phrasing while appearing to cover the behaviour
is worse than no rule, because the tests stay green.

**The corpus also found a bug in this code, not the model.** Asked to quote
lines verbatim from CloudTrail, the model returns `supporting_lines` as JSON
objects rather than strings, and `list[str]` rejected the whole response —
discarding an assessment that was correct (`malicious/critical`, correct IPs and
users). `app/models.py` now re-serializes non-string list items instead of
rejecting them. No structured-log source would have survived the previous
behaviour.

### Still not an accuracy claim

29 held-out samples is enough to expose the failures above and not enough to
put a number in a report. The samples are synthetic and written by the same
person who wrote the detector, so they probe the failure modes that person
thought of. Real labelled logs from a running environment are what would make
these figures defensible.

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
