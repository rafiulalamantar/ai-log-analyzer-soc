"""Score each layer of the system against a labelled corpus.

Two datasets:

    data/samples/   dev set - the rules and prompts were written against these,
                    so a high score here measures agreement, not skill
    data/holdout/   held out - formats and attack classes the rules were never
                    written for, plus benign samples built as traps for
                    specific rules

Configurations: `rules` (deterministic only), each prompt version (model only),
and `<version>+rules` (model with the deterministic floor applied, which is
what /analyze does). The combined row costs no extra inference.

Usage:
    .venv/bin/python scripts/evaluate.py                       # dev set, v1 + v2
    .venv/bin/python scripts/evaluate.py --dataset holdout --versions analyze_v2
    .venv/bin/python scripts/evaluate.py --dataset holdout --versions ""   # rules only
"""
import argparse
import asyncio
import dataclasses
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import llm, mitre, prefilter  # noqa: E402
from app.config import settings as base_settings  # noqa: E402
from app.models import Analysis, Severity  # noqa: E402

VERDICT_FOR = {
    Severity.critical: "malicious",
    Severity.high: "malicious",
    Severity.medium: "suspicious",
    Severity.low: "suspicious",
    Severity.info: "benign",
}


def score(label: dict, verdict: str, severity: str, technique: str | None) -> dict:
    expected = label["mitre_any_of"]
    return {
        "verdict": verdict == label["verdict"],
        "severity": severity == label["severity"],
        "mitre": (technique in expected) if expected else (technique is None),
    }


def detection(rows: list[dict], labels: dict) -> dict:
    """Attack-vs-benign confusion, which is what a SOC actually cares about."""
    tp = fp = fn = tn = 0
    for row in rows:
        if "scores" not in row:
            continue
        truth_attack = labels[row["sample"]]["verdict"] != "benign"
        got_attack = row["verdict"] != "benign"
        if got_attack and truth_attack:
            tp += 1
        elif got_attack and not truth_attack:
            fp += 1
        elif truth_attack:
            fn += 1
        else:
            tn += 1
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
    }


def rules_only(log: str) -> tuple[str, str, str | None]:
    report = prefilter.run(log)
    technique = None
    if report.signals:
        worst = max(report.signals, key=lambda s: prefilter.SEVERITY_ORDER[s.severity])
        technique, _ = mitre.normalize(worst.technique_id)
    return VERDICT_FOR[report.severity_floor], report.severity_floor.value, technique


async def run_model(version: str, data: Path, labels: dict) -> dict[str, dict]:
    llm.settings = dataclasses.replace(base_settings, prompt_version=version)
    out = {}
    for i, name in enumerate(labels, 1):
        print(f"  [{i}/{len(labels)}] {name}", flush=True)
        try:
            analysis, latency = await llm.analyze((data / name).read_text(), name)
        except (llm.LLMUnavailable, llm.LLMBadOutput) as exc:
            out[name] = {"error": type(exc).__name__, "detail": str(exc)[:160]}
            continue
        out[name] = {"analysis": analysis, "latency_ms": latency}
    return out


def rows_for(runs: dict[str, dict] | None, data: Path, labels: dict) -> list[dict]:
    rows = []
    for name, label in labels.items():
        if runs is None:
            verdict, severity, technique = rules_only((data / name).read_text())
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
            "sample": name, "verdict": verdict, "severity": severity, "mitre": technique,
            "latency_ms": latency, "scores": score(label, verdict, severity, technique),
        })
    return rows


def combine(runs: dict[str, dict], data: Path) -> dict[str, dict]:
    out = {}
    for name, result in runs.items():
        if "error" in result:
            out[name] = result
            continue
        analysis: Analysis = result["analysis"].model_copy(deep=True)
        prefilter.apply_floor(analysis, prefilter.run((data / name).read_text()))
        out[name] = {"analysis": analysis, "latency_ms": result["latency_ms"]}
    return out


def render(dataset: str, all_rows: dict[str, list[dict]], labels: dict) -> str:
    attacks = sum(1 for v in labels.values() if v["verdict"] != "benign")
    in_scope = sum(1 for v in labels.values() if v.get("in_rule_scope"))
    out = [
        f"# Evaluation - {dataset}", "",
        f"Model: `{base_settings.ollama_model}` | {len(labels)} samples "
        f"({attacks} attack / {len(labels) - attacks} benign) | {in_scope} within the rules' scope", "",
        "## Summary", "",
        "| configuration | verdict | severity | technique | fields | precision | recall | FP | mean latency |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for config, rows in all_rows.items():
        ok = [r for r in rows if "scores" in r]
        per = {k: sum(r["scores"][k] for r in ok) for k in ("verdict", "severity", "mitre")}
        d = detection(rows, labels)
        lat = [r["latency_ms"] for r in ok]
        mean = f"{sum(lat) // len(lat)}ms" if lat and any(lat) else "<1ms"
        n = len(ok)
        pr = f"{d['precision']:.2f}" if d["precision"] is not None else "-"
        rc = f"{d['recall']:.2f}" if d["recall"] is not None else "-"
        out.append(
            f"| {config} | {per['verdict']}/{n} | {per['severity']}/{n} | {per['mitre']}/{n} "
            f"| **{sum(per.values())}/{n * 3}** | {pr} | {rc} | {d['fp']} | {mean} |"
        )

    out += ["", "Precision and recall are over attack-vs-benign, which is the decision an",
            "analyst acts on. FP counts benign samples reported as an attack.", ""]

    for config, rows in all_rows.items():
        out += ["", f"## {config}", "", "| sample | in scope | verdict | severity | technique | v | s | m |",
                "|---|---|---|---|---|---|---|---|"]
        for r in rows:
            scope = "yes" if labels[r["sample"]].get("in_rule_scope") else "no"
            if "error" in r:
                out.append(f"| {r['sample']} | {scope} | **{r['error']}** | | | | | |")
                continue
            s = r["scores"]
            t = lambda b: "ok" if b else "X"  # noqa: E731
            out.append(
                f"| {r['sample']} | {scope} | {r['verdict']} | {r['severity']} | {r['mitre'] or '-'} "
                f"| {t(s['verdict'])} | {t(s['severity'])} | {t(s['mitre'])} |"
            )
    return "\n".join(out) + "\n"


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="samples", choices=("samples", "holdout"))
    ap.add_argument("--versions", default="analyze_v1,analyze_v2",
                    help="comma-separated prompt versions; empty for rules only")
    args = ap.parse_args()

    data = Path("data") / args.dataset
    labels = json.loads((data / "labels.json").read_text())
    versions = [v for v in args.versions.split(",") if v]

    all_rows = {"rules": rows_for(None, data, labels)}
    print(f"scored rules over {len(labels)} samples (no model)", flush=True)

    runs = {}
    for version in versions:
        print(f"running {version} ...", flush=True)
        runs[version] = await run_model(version, data, labels)
        all_rows[version] = rows_for(runs[version], data, labels)
    if versions:
        last = versions[-1]
        all_rows[f"{last}+rules"] = rows_for(combine(runs[last], data), data, labels)

    report = render(args.dataset, all_rows, labels)
    out = Path("data/eval") / f"results_{args.dataset}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report)
    print("\n" + report.split("\n## rules")[0])
    print(f"written to {out}")


if __name__ == "__main__":
    asyncio.run(main())
