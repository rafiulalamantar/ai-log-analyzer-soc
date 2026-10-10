"""Deterministic rule layer, run before the model sees anything.

Three jobs:

1. Catch what an 8B model demonstrably misses. In testing, llama3.1:8b called a
   *successful* SSH brute force "suspicious/medium" and ignored a sudo
   `curl | sh` entirely. A regex does not have opinions.
2. Impose a severity floor the model cannot talk its way under, so a missed
   escalation degrades into a correct-but-terse alert instead of a wrong one.
3. Make volume affordable. Prompt evaluation, not model loading, is what costs
   ~20s per request, and that cost is per-call regardless of how dull the logs
   are. Rules are microseconds.
"""
import re
from dataclasses import dataclass, field

from .models import PrefilterReport, Severity, Signal

SEVERITY_ORDER = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}

# A source producing at least this many failures before a success is treated as
# a successful brute force rather than a user who mistyped their password.
FAILURES_BEFORE_SUCCESS = 3
FAILURES_FOR_ATTEMPT = 5
USERS_FOR_SPRAY = 4

SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s[\d:]{8})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w\-./]+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

FAILED_AUTH = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>[\w\-.$]+)", re.I)
ACCEPTED_AUTH = re.compile(r"Accepted (?:password|publickey) for (?P<user>[\w\-.$]+)", re.I)
PIPE_TO_SHELL = re.compile(r"(?:curl|wget|fetch)\s[^|;]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b", re.I)
ROOT_ACCOUNT = re.compile(r"new user:.*\b(?:UID|GID)=0\b", re.I)
LOG_TAMPER = re.compile(
    r">\s*/var/log/\S+|rm\s+(?:-\w+\s+)*/var/log/\S+|journalctl\s+--vacuum|"
    r"truncate\s+-s\s*0\s+/var/log/\S+|history\s+-c",
    re.I,
)
SHADOW_READ = re.compile(r"(?:cat|cp|less|more|tail|scp)\s+\S*/etc/(?:shadow|gshadow)\b", re.I)
SERVICE_ACCOUNTS = frozenset({"www-data", "nobody", "apache", "nginx", "postgres", "mysql", "daemon"})
# Two shapes to handle: the syslog parser moves "sudo:" into Event.process,
# leaving "www-data : USER=root ...", while an unparsed line keeps the prefix.
SUDO_PREFIXED = re.compile(r"sudo:\s*(?P<user>[\w\-.$]+)\s*:", re.I)
SUDO_INVOKER = re.compile(r"^\s*(?P<user>[\w\-.$]+)\s*:\s*(?:TTY|PWD|USER)=", re.I)


@dataclass
class Event:
    """One parsed log line. `message` is the part after the process name."""

    raw: str
    message: str
    host: str | None = None
    process: str | None = None
    timestamp: str | None = None
    ips: list[str] = field(default_factory=list)


def parse(log: str) -> list[Event]:
    """Normalize raw log text into events, keeping unparseable lines usable."""
    events = []
    for line in log.splitlines():
        line = line.strip()
        if not line:
            continue
        m = SYSLOG.match(line)
        if m:
            events.append(
                Event(
                    raw=line,
                    message=m.group("message"),
                    host=m.group("host"),
                    process=m.group("process"),
                    timestamp=m.group("ts"),
                    ips=IPV4.findall(line),
                )
            )
        else:
            # Unrecognised format still gets the content rules applied to it.
            events.append(Event(raw=line, message=line, ips=IPV4.findall(line)))
    return events


def _auth_signals(events: list[Event]) -> list[Signal]:
    """Correlate failures and successes per source address."""
    failures: dict[str, list[Event]] = {}
    users: dict[str, set[str]] = {}
    successes: dict[str, list[tuple[Event, str]]] = {}

    for event in events:
        source = event.ips[0] if event.ips else None
        if not source:
            continue
        if (failed := FAILED_AUTH.search(event.message)):
            failures.setdefault(source, []).append(event)
            users.setdefault(source, set()).add(failed.group("user"))
        elif (ok := ACCEPTED_AUTH.search(event.message)):
            successes.setdefault(source, []).append((event, ok.group("user")))

    signals = []
    for source, failed_events in sorted(failures.items()):
        count = len(failed_events)
        hit = successes.get(source)

        if hit and count >= FAILURES_BEFORE_SUCCESS:
            event, user = hit[0]
            signals.append(
                Signal(
                    rule_id="R001",
                    name="Successful brute force",
                    severity=Severity.critical,
                    technique_id="T1110",
                    detail=(
                        f"{count} failed authentications from {source} were followed by a "
                        f"successful login as '{user}'. The credentials are now known to the attacker."
                    ),
                    lines=[e.raw for e in failed_events[:3]] + [event.raw],
                )
            )
        elif count >= FAILURES_FOR_ATTEMPT:
            signals.append(
                Signal(
                    rule_id="R002",
                    name="Brute force attempt",
                    severity=Severity.medium,
                    technique_id="T1110",
                    detail=f"{count} failed authentications from {source} with no success observed.",
                    lines=[e.raw for e in failed_events[:5]],
                )
            )

        if len(users.get(source, ())) >= USERS_FOR_SPRAY:
            targeted = sorted(users[source])
            signals.append(
                Signal(
                    rule_id="R003",
                    name="Password spraying",
                    severity=Severity.medium,
                    technique_id="T1110.003",
                    detail=f"{source} attempted {len(targeted)} distinct accounts: {', '.join(targeted)}.",
                    lines=[e.raw for e in failed_events[:5]],
                )
            )
    return signals


def _sudo_invoker(event: Event) -> str | None:
    """Who called sudo, whichever shape the line arrived in."""
    if event.process and event.process.lower() == "sudo":
        if (m := SUDO_INVOKER.match(event.message)):
            return m.group("user")
    if (m := SUDO_PREFIXED.search(event.message)):
        return m.group("user")
    return None


def _content_signals(events: list[Event]) -> list[Signal]:
    """Line-local rules: the command itself is the indicator."""
    checks = (
        (PIPE_TO_SHELL, "R004", "Remote code execution", Severity.critical, "T1059.004",
         "Remote content is piped directly into a shell interpreter."),
        (ROOT_ACCOUNT, "R005", "Root account created", Severity.critical, "T1136.001",
         "A new account was created with UID or GID 0."),
        (LOG_TAMPER, "R006", "Log tampering", Severity.high, "T1070.002",
         "System logs or shell history were cleared or truncated."),
        (SHADOW_READ, "R007", "Credential store accessed", Severity.high, "T1003.008",
         "The shadow password file was read or copied."),
    )
    signals = []
    for event in events:
        for pattern, rule_id, name, severity, technique, detail in checks:
            if pattern.search(event.message):
                signals.append(
                    Signal(rule_id=rule_id, name=name, severity=severity,
                           technique_id=technique, detail=detail, lines=[event.raw])
                )
        invoker = _sudo_invoker(event)
        if invoker and invoker.lower() in SERVICE_ACCOUNTS:
            signals.append(
                Signal(
                    rule_id="R008",
                    name="Sudo by service account",
                    severity=Severity.high,
                    technique_id="T1548.003",
                    detail=(
                        f"'{invoker}' is a service account and should not invoke sudo; "
                        "this usually means the service it runs was compromised."
                    ),
                    lines=[event.raw],
                )
            )
    return signals


def run(log: str) -> PrefilterReport:
    """Apply every rule and summarize what fired."""
    events = parse(log)
    signals = _auth_signals(events) + _content_signals(events)
    floor = max((s.severity for s in signals), key=lambda s: SEVERITY_ORDER[s], default=Severity.info)
    return PrefilterReport(
        events_parsed=len(events),
        signals=signals,
        severity_floor=floor,
        # Nothing fired: a model call is unlikely to find anything either, but
        # it is still made, because rules only know what they were taught.
        clean=not signals,
    )


def apply_floor(analysis, report: PrefilterReport) -> bool:
    """Raise the model's assessment to meet the rules. Returns True if changed.

    The rules are never lowered to match the model: a regex that matched
    `curl | sh` is right, and a model that called it medium is wrong.
    """
    changed = False
    if SEVERITY_ORDER[analysis.severity] < SEVERITY_ORDER[report.severity_floor]:
        analysis.severity = report.severity_floor
        changed = True
    if report.severity_floor in (Severity.high, Severity.critical) and analysis.verdict != "malicious":
        from .models import Verdict

        analysis.verdict = Verdict.malicious
        changed = True
    # Fill in a technique the model declined to name but a rule identified.
    if analysis.mitre.technique_id is None and report.signals:
        from . import mitre

        worst = max(report.signals, key=lambda s: SEVERITY_ORDER[s.severity])
        tid, name = mitre.normalize(worst.technique_id)
        if tid:
            analysis.mitre.technique_id, analysis.mitre.technique_name = tid, name
            changed = True
    return changed
