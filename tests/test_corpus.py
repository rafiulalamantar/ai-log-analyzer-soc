"""Corpus integrity. A mislabelled sample silently corrupts every evaluation."""
import json
from pathlib import Path

import pytest

from app.mitre import CATALOG
from app.models import Severity, Verdict

DATASETS = ("samples", "holdout")


def labelled(dataset: str) -> dict:
    return json.loads((Path("data") / dataset / "labels.json").read_text())


def log_files(dataset: str) -> set[str]:
    return {p.name for p in (Path("data") / dataset).glob("*.log")}


@pytest.mark.parametrize("dataset", DATASETS)
def test_every_log_file_is_labelled(dataset):
    assert log_files(dataset) == set(labelled(dataset)), (
        "a log file without a label is never evaluated; a label without a file crashes the harness"
    )


@pytest.mark.parametrize("dataset", DATASETS)
def test_verdicts_and_severities_are_valid(dataset):
    for name, label in labelled(dataset).items():
        assert label["verdict"] in {v.value for v in Verdict}, name
        assert label["severity"] in {s.value for s in Severity}, name


@pytest.mark.parametrize("dataset", DATASETS)
def test_expected_techniques_exist_in_the_catalogue(dataset):
    # A label naming a technique mitre.normalize() would drop is unscoreable:
    # the model could answer correctly and still be marked wrong.
    for name, label in labelled(dataset).items():
        for technique in label["mitre_any_of"]:
            assert technique in CATALOG, f"{name}: {technique} missing from CATALOG"


@pytest.mark.parametrize("dataset", DATASETS)
def test_benign_samples_expect_no_technique(dataset):
    for name, label in labelled(dataset).items():
        if label["verdict"] == "benign":
            assert label["mitre_any_of"] == [], name
            assert label["severity"] == "info", name


@pytest.mark.parametrize("dataset", DATASETS)
def test_attacks_name_at_least_one_technique(dataset):
    for name, label in labelled(dataset).items():
        if label["verdict"] != "benign":
            assert label["mitre_any_of"], name


@pytest.mark.parametrize("dataset", DATASETS)
def test_every_label_explains_itself(dataset):
    for name, label in labelled(dataset).items():
        assert label.get("note", "").strip(), f"{name}: a label without a rationale cannot be reviewed"


@pytest.mark.parametrize("dataset", DATASETS)
def test_samples_are_not_empty(dataset):
    for name in labelled(dataset):
        assert (Path("data") / dataset / name).read_text().strip(), name


def test_holdout_records_rule_scope():
    # The in_scope flag is what separates "the rules failed" from
    # "the rules were never meant to catch this".
    for name, label in labelled("holdout").items():
        assert isinstance(label.get("in_rule_scope"), bool), name


def test_holdout_is_balanced_enough_to_measure_false_positives():
    labels = labelled("holdout")
    benign = [n for n, l in labels.items() if l["verdict"] == "benign"]
    attacks = [n for n, l in labels.items() if l["verdict"] != "benign"]
    assert len(benign) >= 8, "too few benign samples to say anything about false positives"
    assert len(attacks) >= 15
    assert len(labels) >= 25


def test_holdout_covers_formats_the_rules_were_not_written_for():
    # The dev corpus is all syslog. If the holdout were too, it would not test
    # the parser at all.
    joined = "".join((Path("data/holdout") / n).read_text() for n in labelled("holdout"))
    assert '"eventName"' in joined, "no cloud (JSON) logs"
    assert "EventID=4625" in joined, "no Windows event logs"
    assert 'HTTP/1.1"' in joined, "no web access logs"
