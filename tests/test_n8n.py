"""The n8n workflow is JSON that n8n runs, so nothing else checks it. These
tests catch the drift that would break it silently: a renamed API field, a
dangling connection, or a write outside the one directory n8n may touch."""
import json
import re
from pathlib import Path

import pytest

from app.models import Analysis, AnalyzeResponse, Mitre, PrefilterReport, Signal

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = json.loads((ROOT / "n8n" / "soc_triage.json").read_text())
NODES = {n["name"]: n for n in WORKFLOW["nodes"]}


def code(name: str) -> str:
    return NODES[name]["parameters"]["jsCode"]


def reads(js: str, var: str) -> set[str]:
    """Field names read as `<var>.field` in a Code node."""
    return set(re.findall(rf"(?<![\w$]){re.escape(var)}\.(\w+)", js))


def test_every_connection_points_at_a_node():
    for source, outputs in WORKFLOW["connections"].items():
        assert source in NODES
        for branch in outputs["main"]:
            for target in branch:
                assert target["node"] in NODES, f"{source} -> {target['node']}"


def test_every_node_except_the_trigger_has_an_input():
    targets = {t["node"] for o in WORKFLOW["connections"].values() for b in o["main"] for t in b}
    assert set(NODES) - targets == {"Log received"}


def test_webhook_replies_only_after_triage():
    hook = NODES["Log received"]["parameters"]
    assert hook["path"] == "soc-triage"
    # The collector relies on this for backpressure; see scripts/ship_logs.py.
    assert hook["responseMode"] == "responseNode"


def test_api_is_addressed_by_ipv4():
    # Node resolves localhost to ::1 first and uvicorn listens on IPv4: the
    # first live run of this workflow failed with ECONNREFUSED ::1:8000.
    assert "http://127.0.0.1:8000" in code("Prepare")
    assert "localhost" not in code("Prepare").split("const API")[1].splitlines()[0]


def test_analysis_failure_is_recorded_not_dropped():
    assert NODES["Full analysis"]["onError"] == "continueErrorOutput"
    error_branch = WORKFLOW["connections"]["Full analysis"]["main"][1]
    assert [t["node"] for t in error_branch] == ["Analysis failed"]


@pytest.mark.parametrize("node", ["Append to incidents.jsonl", "Append to alerts.jsonl"])
def test_writes_append_inside_the_allowed_directory(node):
    params = NODES[node]["parameters"]
    assert params["fileName"].startswith("data/incidents/")
    assert params["options"]["append"] is True
    # n8n/start.sh restricts file access to exactly this directory.
    assert 'N8N_RESTRICT_FILE_ACCESS_TO="$PWD/data/incidents"' in (ROOT / "n8n" / "start.sh").read_text()


def test_incident_record_reads_only_fields_the_api_returns():
    js = code("Incident record")
    assert reads(js, "a") <= set(Analysis.model_fields)
    assert reads(js, "a.mitre") <= set(Mitre.model_fields)
    assert reads(js, "p") <= set(PrefilterReport.model_fields)
    assert reads(js, "$json") <= set(AnalyzeResponse.model_fields)
    assert reads(js, "s") <= set(Signal.model_fields)


def test_rule_alert_reads_only_fields_the_api_returns():
    js = code("Rule alert")
    assert reads(js, "$json") <= set(PrefilterReport.model_fields)
    assert reads(js, "s") <= set(Signal.model_fields)


def test_alert_threshold_matches_the_rules_verdict_mapping():
    # Rules alert at high/critical; so does the model branch.
    floor_values = {c["rightValue"] for c in
                    NODES["Rules rate it high or critical?"]["parameters"]["conditions"]["conditions"]}
    assert floor_values == {"high", "critical"}
    assert "['high', 'critical'].includes(a.severity)" in code("Incident record")
