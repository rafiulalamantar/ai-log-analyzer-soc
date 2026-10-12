"""The catalogue layer: constrain the prompt, repair the output."""
import dataclasses
import json
import re

import pytest

from app import llm, mitre, prefilter
from app.config import PROMPT_DIR, settings

PROMPT_VERSIONS = sorted(p.stem for p in PROMPT_DIR.glob("analyze_v*.txt"))


def test_known_id_keeps_catalogue_name():
    assert mitre.normalize("T1110") == ("T1110", "Brute Force")


def test_model_supplied_name_is_overridden_by_catalogue():
    # llama3.1:8b returned "Exploit Public-Facing Service" for T1210; the real
    # name is "Exploitation of Remote Services". The catalogue wins.
    _, name = mitre.normalize("T1210")
    assert name == "Exploitation of Remote Services"


def test_unknown_id_is_dropped_not_guessed():
    assert mitre.normalize("T9999") == (None, None)


def test_unlisted_subtechnique_falls_back_to_parent():
    assert mitre.normalize("T1110.004") == ("T1110", "Brute Force")


def test_lowercase_and_whitespace_tolerated():
    assert mitre.normalize("  t1105 ") == ("T1105", "Ingress Tool Transfer")


def test_none_stays_none():
    assert mitre.normalize(None) == (None, None)


def test_catalogue_is_injected_into_the_prompt():
    prompt = llm.build_prompt("Failed password for root", "auth.log")
    assert "T1110  Brute Force" in prompt
    assert "{mitre_catalog}" not in prompt


@pytest.mark.parametrize("version", PROMPT_VERSIONS)
def test_prompt_has_no_unsubstituted_placeholders(monkeypatch, version):
    monkeypatch.setattr(llm, "settings", dataclasses.replace(settings, prompt_version=version))
    prompt = llm.build_prompt("some log", None)
    for placeholder in ("{log}", "{source}", "{mitre_catalog}"):
        assert placeholder not in prompt


def worked_examples(version: str) -> list[tuple[str, dict]]:
    text = (PROMPT_DIR / f"{version}.txt").read_text()
    pairs = re.findall(r"Input:\n(.*?)\nOutput:\n(\{.*?\})\n", text, re.S)
    return [(log, json.loads(out)) for log, out in pairs]


def test_v3_worked_examples_agree_with_the_rule_layer():
    # analyze_v2 fails this: its brute-force example graded two failures then a
    # success as critical, while R001 needs three. The model learned the example,
    # and paged on mistyped passwords in both datasets. Prompt and rules must
    # teach the same threshold.
    examples = worked_examples("analyze_v3")
    assert len(examples) >= 4
    for log, out in examples:
        report = prefilter.run(log)
        if out["verdict"] == "benign":
            assert report.clean, log
        if out["mitre"]["technique_id"] == "T1110":
            assert "R001" in {s.rule_id for s in report.signals}, log
