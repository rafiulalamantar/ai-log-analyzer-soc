"""The catalogue layer: constrain the prompt, repair the output."""
from app import llm, mitre


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


def test_prompt_has_no_unsubstituted_placeholders():
    prompt = llm.build_prompt("some log", None)
    for placeholder in ("{log}", "{source}", "{mitre_catalog}"):
        assert placeholder not in prompt
