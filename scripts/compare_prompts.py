"""Score prompt versions against the labelled corpus.

Seed of the Phase 5 evaluation harness: it answers "did changing the prompt
actually help", which is the table the project report's Chapter 5 needs.

Usage:
    .venv/bin/python scripts/compare_prompts.py analyze_v1 analyze_v2
"""
import asyncio
import dataclasses
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import llm  # noqa: E402
from app.config import settings as base_settings  # noqa: E402

SAMPLES = Path("data/samples")
OUT = Path("data/eval/prompt_comparison.md")


def score(label: dict, got) -> dict:
    expected_ids = label["mitre_any_of"]
    got_id = got.mitre.technique_id
    return {
        "verdict": got.verdict.value == label["verdict"],
        "severity": got.severity.value == label["severity"],
        # An empty expectation means "no technique should be reported".
        "mitre": (got_id in expected_ids) if expected_ids else (got_id is None),
    }


async def run_version(version: str, labels: dict) -> list[dict]:
    llm.settings = dataclasses.replace(base_settings, prompt_version=version)
    rows = []
    for name, label in labels.items():
        log = (SAMPLES / name).read_text()
        try:
            analysis, latency = await llm.analyze(log, name)
        except (llm.LLMUnavailable, llm.LLMBadOutput) as exc:
            rows.append({"sample": name, "error": type(exc).__name__, "detail": str(exc)[:120]})
            continue
        rows.append(
            {
                "sample": name,
                "verdict": analysis.verdict.value,
                "severity": analysis.severity.value,
                "mitre": analysis.mitre.technique_id,
                "attack_type": analysis.attack_type,
                "latency_ms": latency,
                "scores": score(label, analysis),
            }
        )
    return rows


def render(results: dict[str, list[dict]], labels: dict) -> str:
    out = ["# Prompt comparison", "", f"Model: `{base_settings.ollama_model}`", ""]
    out += ["## Expected", "", "| sample | verdict | severity | acceptable technique |", "|---|---|---|---|"]
    for name, l in labels.items():
        ids = ", ".join(l["mitre_any_of"]) or "(none)"
        out.append(f"| {name} | {l['verdict']} | {l['severity']} | {ids} |")

    for version, rows in results.items():
        out += ["", f"## {version}", "", "| sample | verdict | severity | technique | v | s | m | latency |", "|---|---|---|---|---|---|---|---|"]
        for r in rows:
            if "error" in r:
                out.append(f"| {r['sample']} | **{r['error']}** | | | | | | |")
                continue
            s = r["scores"]
            tick = lambda b: "ok" if b else "X"  # noqa: E731
            out.append(
                f"| {r['sample']} | {r['verdict']} | {r['severity']} | {r['mitre'] or '-'} "
                f"| {tick(s['verdict'])} | {tick(s['severity'])} | {tick(s['mitre'])} | {r['latency_ms']}ms |"
            )
        ok = [r for r in rows if "scores" in r]
        total = len(ok) * 3
        hits = sum(sum(r["scores"].values()) for r in ok)
        lat = [r["latency_ms"] for r in ok]
        out += [
            "",
            f"**{version}: {hits}/{total} fields correct"
            + (f", mean latency {sum(lat) // len(lat)}ms**" if lat else "**"),
        ]
    return "\n".join(out) + "\n"


async def main() -> None:
    versions = sys.argv[1:] or ["analyze_v1", "analyze_v2"]
    labels = json.loads((SAMPLES / "labels.json").read_text())
    results = {}
    for v in versions:
        print(f"running {v} ...", flush=True)
        results[v] = await run_version(v, labels)
    report = render(results, labels)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(report)
    print("\n" + report)
    print(f"written to {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
