"""Score each layer of the system against the labelled corpus.

Four configurations, so the report can show what each layer contributes:

    rules              deterministic only, no model (microseconds)
    analyze_v1         model only, original prompt
    analyze_v2         model only, escalation rules + few-shot
    analyze_v2+rules   model with the deterministic severity floor applied

The combined row needs no extra inference: it is the v2 assessment with
prefilter.apply_floor() run over a copy, which is exactly what /analyze does.

Usage:
    .venv/bin/python scripts/evaluate.py
"""
import asyncio
import dataclasses
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import llm, mitre, prefilter  # noqa: E402
from app.config import settings as base_settings  # noqa: E402
from app.models import Analysis, Severity  # noqa: E402

SAMPLES = Path("data/samples")
OUT = Path("data/eval/results.md")
MODEL_VERSIONS = ("analyze_v1", "analyze_v2")


def score(label: dict, verdict: str, severity: str, technique: str | None) -> dict:
    expected = label["mitre_any_of"]
    return {
        "verdict": verdict == label["verdict"],
        "severity": severity == label["severity"],
        "mitre": (technique in expected) if expected else (technique is None),
    }


def rules_only(log: str) -> tuple[str, str, str | None]:
    """Translate a prefilter report into a verdict, for a fair baseline."""
    report = prefilter.run(log)
    floor = report.severity_floor
    verdict = {
        Severity.critical: "malicious",
        Severity.high: "malicious",
        Severity.medium: "suspicious",
        Severity.low: "suspicious",
        Severity.info: "benign",
    }[floor]
    technique = None
    if report.signals:
        worst = max(report.signals, key=lambda s: prefilter.SEVERITY_ORDER[s.severity])
        technique, _ = mitre.normalize(worst.technique_id)
    return verdict, floor.value, technique


async def run_model(version: str, labels: dict) -> dict[str, dict]:
    llm.settings = dataclasses.replace(base_settings, prompt_version=version)
    out = {}
    for name in labels:
        log = (SAMPLES / name).read_text()
        try:
            analysis, latency = await llm.analyze(log, name)
        except (llm.LLMUnavailable, llm.LLMBadOutput) as exc:
            out[name] = {"error": type(exc).__name__}
            continue
        out[name] = {"analysis": analysis, "latency_ms": latency}
    return out


def combine(model_runs: dict[str, dict], labels: dict) -> dict[str, dict]:
    """v2 plus the deterministic floor — no second inference pass."""
    out = {}
    for name, result in model_runs.items():
        if "error" in result:
            out[name] = result
            continue
        analysis: Analysis = result["analysis"].model_copy(deep=True)
        report = prefilter.run((SAMPLES / name).read_text())
        prefilter.apply_floor(analysis, report)
        out[name] = {"analysis": analysis, "latency_ms": result["latency_ms"]}
    return out


def rows_for(config: str, runs: dict[str, dict], labels: dict) -> list[dict]:
    rows = []
    for name, label in labels.items():
        if config == "rules":
            verdict, severity, technique = rules_only((SAMPLES / name).read_text())
            latency = 0
        else:
            result = runs[name]
            if "error" in result:
                rows.append({"sample": name, "error": result["error"]})
                continue
            a = result["analysis"]
            verdict, severity, technique = a.verdict.value, a.severity.value, a.mitre.technique_id
            latency = result["latency_ms"]
        rows.append({
            "sample": name, "verdict": verdict, "severity": severity,
            "mitre": technique, "latency_ms": latency,
            "scores": score(label, verdict, severity, technique),
        })
    return rows


def render(all_rows: dict[str, list[dict]], labels: dict) -> str:
    out = ["# Evaluation", "", f"Model: `{base_settings.ollama_model}` | {len(labels)} labelled samples", ""]
    out += ["## Ground truth", "", "| sample | verdict | severity | acceptable technique | why |", "|---|---|---|---|---|"]
    for name, l in labels.items():
        out.append(f"| {name} | {l['verdict']} | {l['severity']} | {', '.join(l['mitre_any_of']) or '(none)'} | {l['note']} |")

    out += ["", "## Summary", "", "| configuration | verdict | severity | technique | total | mean latency |", "|---|---|---|---|---|---|"]
    for config, rows in all_rows.items():
        ok = [r for r in rows if "scores" in r]
        per = {k: sum(r["scores"][k] for r in ok) for k in ("verdict", "severity", "mitre")}
        total = sum(per.values())
        lat = [r["latency_ms"] for r in ok]
        mean = f"{sum(lat) // len(lat)}ms" if lat and any(lat) else "<1ms"
        n = len(ok)
        out.append(
            f"| {config} | {per['verdict']}/{n} | {per['severity']}/{n} | {per['mitre']}/{n} "
            f"| **{total}/{n * 3}** | {mean} |"
        )

    for config, rows in all_rows.items():
        out += ["", f"## {config}", "", "| sample | verdict | severity | technique | v | s | m |", "|---|---|---|---|---|---|---|"]
        for r in rows:
            if "error" in r:
                out.append(f"| {r['sample']} | **{r['error']}** | | | | | |")
                continue
            s = r["scores"]
            t = lambda b: "ok" if b else "X"  # noqa: E731
            out.append(
                f"| {r['sample']} | {r['verdict']} | {r['severity']} | {r['mitre'] or '-'} "
                f"| {t(s['verdict'])} | {t(s['severity'])} | {t(s['mitre'])} |"
            )
    return "\n".join(out) + "\n"


async def main() -> None:
    labels = json.loads((SAMPLES / "labels.json").read_text())
    all_rows = {"rules": rows_for("rules", {}, labels)}
    print("scored rules (no model)", flush=True)

    model_runs = {}
    for version in MODEL_VERSIONS:
        print(f"running {version} over {len(labels)} samples ...", flush=True)
        model_runs[version] = await run_model(version, labels)
        all_rows[version] = rows_for(version, model_runs[version], labels)

    all_rows["analyze_v2+rules"] = rows_for(
        "analyze_v2+rules", combine(model_runs["analyze_v2"], labels), labels
    )

    report = render(all_rows, labels)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(report)
    print("\n" + report)
    print(f"written to {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
