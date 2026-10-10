"""A curated MITRE ATT&CK catalogue for log analysis.

Free-recalling technique IDs is where a small local model is weakest: in
testing, llama3.1:8b labelled both an SSH brute force and a sudo-based
privilege escalation as "T1210". So the catalogue serves two purposes — it is
injected into the prompt to constrain the model's choice, and it is used
afterwards to repair the technique *name*, which is looked up here rather than
trusted from the model.

Scoped to techniques that are actually observable in host and auth logs.
"""

CATALOG: dict[str, str] = {
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1078": "Valid Accounts",
    "T1021.004": "Remote Services: SSH",
    "T1136.001": "Create Account: Local Account",
    "T1098": "Account Manipulation",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1105": "Ingress Tool Transfer",
    "T1190": "Exploit Public-Facing Application",
    "T1210": "Exploitation of Remote Services",
    "T1046": "Network Service Discovery",
    "T1595": "Active Scanning",
    "T1003.008": "OS Credential Dumping: /etc/passwd and /etc/shadow",
    "T1070.002": "Indicator Removal: Clear Linux or Mac System Logs",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1543.002": "Create or Modify System Process: Systemd Service",
    "T1033": "System Owner/User Discovery",
    "T1082": "System Information Discovery",
    "T1041": "Exfiltration Over C2 Channel",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1496": "Resource Hijacking",
}


def catalog_for_prompt() -> str:
    """The catalogue as prompt lines, so the model picks instead of recalling."""
    return "\n".join(f"  {tid}  {name}" for tid, name in CATALOG.items())


def normalize(technique_id: str | None) -> tuple[str | None, str | None]:
    """Return a catalogue-backed (id, name), or (None, None) if unrecognised.

    An ID the model invented is dropped rather than passed on: a wrong
    technique is worse for an analyst than an absent one.
    """
    if not technique_id:
        return None, None
    tid = technique_id.strip().upper()
    if tid in CATALOG:
        return tid, CATALOG[tid]
    # Accept a sub-technique guess by falling back to its parent, e.g. T1110.004.
    parent = tid.split(".")[0]
    if parent in CATALOG:
        return parent, CATALOG[parent]
    return None, None
