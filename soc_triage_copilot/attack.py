"""A deliberately small ATT&CK mapping table.

A full ATT&CK bundle is 40MB of JSON and answers questions this tool does not
ask. What an L2 analyst needs is: which technique does this alert represent, and
what does the presence of several techniques in one case tell me? That fits in a
readable table, which also makes the mapping auditable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .models import Alert


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    keywords: tuple[str, ...]
    critical: bool = False
    recommendation: str = ""


TECHNIQUES: tuple[Technique, ...] = (
    Technique(
        "T1486", "Data Encrypted for Impact", "Impact",
        ("ransom", "encrypt", "file extension", "locked", "decrypt note", "readme.txt"),
        critical=True,
        recommendation="Isolate the host, snapshot disk state, and check backup integrity before any restore.",
    ),
    Technique(
        "T1490", "Inhibit System Recovery", "Impact",
        ("vssadmin", "shadow copy", "shadowcopy", "wbadmin", "delete catalog", "bcdedit"),
        critical=True,
        recommendation="Treat as pre-encryption staging: contain immediately and verify backups are offline.",
    ),
    Technique(
        "T1003.001", "LSASS Memory", "Credential Access",
        ("lsass", "mimikatz", "procdump", "comsvcs", "minidump", "credential dump"),
        critical=True,
        recommendation="Reset credentials for accounts active on the host and hunt for lateral use of the dump.",
    ),
    Technique(
        "T1059.001", "PowerShell", "Execution",
        ("powershell", "encodedcommand", "-enc", "pwsh", "script block"),
        recommendation="Pull the full script block from the EDR, deobfuscate it, and hash any dropped files.",
    ),
    Technique(
        "T1059.003", "Windows Command Shell", "Execution",
        ("cmd.exe", "command shell", "batch script"),
        recommendation="Extract the parent process and command line lineage for the shell session.",
    ),
    Technique(
        "T1053.005", "Scheduled Task", "Persistence",
        ("schtasks", "scheduled task", "at.exe", "task scheduler"),
        recommendation="List the task definition, its author, and the binary it launches before deletion.",
    ),
    Technique(
        "T1547.001", "Registry Run Keys", "Persistence",
        ("run key", "runonce", "winlogon", "registry run"),
        recommendation="Capture the registry value data and the file hash it points to.",
    ),
    Technique(
        "T1543.003", "Windows Service", "Persistence",
        ("service creation", "7045", "new service", "sc create"),
        recommendation="Verify the service binary signature and the account context used to install it.",
    ),
    Technique(
        "T1566", "Phishing", "Initial Access",
        ("phishing", "suspicious email", "attachment", "spearphish", "macro document"),
        recommendation="Scope the campaign: search all recipients of the same sender, subject and attachment hash.",
    ),
    Technique(
        "T1114.003", "Email Forwarding Rule", "Collection",
        ("inbox rule", "forwarding", "redirectto", "forwardto", "mail rule"),
        recommendation="Remove the rule, then review the mailbox audit log for messages already exfiltrated.",
    ),
    Technique(
        "T1110.003", "Password Spraying", "Credential Access",
        ("password spray", "many accounts", "failed logon", "brute force", "4625"),
        recommendation="Block the source range, confirm no account succeeded, and force a reset on any that did.",
    ),
    Technique(
        "T1078", "Valid Accounts", "Defense Evasion",
        ("impossible travel", "valid account", "anomalous sign-in", "unfamiliar sign-in"),
        recommendation="Validate the sign-in against the user, then review MFA method changes and token issuance.",
    ),
    Technique(
        "T1021.001", "Remote Desktop Protocol", "Lateral Movement",
        ("rdp", "remote desktop", "3389", "tscon"),
        recommendation="Identify the source host and account, then check for RDP tunnelling or credential reuse.",
    ),
    Technique(
        "T1071.001", "Web Protocols", "Command and Control",
        ("beacon", "c2", "callback", "command and control", "jitter"),
        recommendation="Sinkhole or block the destination and inspect proxy logs for other hosts talking to it.",
    ),
    Technique(
        "T1562.001", "Disable or Modify Tools", "Defense Evasion",
        ("defender exclusion", "exclusionpath", "disable antivirus", "tamper protection"),
        critical=True,
        recommendation="Re-enable protection, capture the exclusion list, and treat the host as compromised.",
    ),
)


def _text_of(alert: Alert) -> str:
    entity_text = " ".join(str(value) for value in alert.entities.values())
    return f"{alert.rule} {alert.description} {entity_text}".lower()


def match(alert: Alert) -> list[Technique]:
    """Return every technique whose keywords appear in the alert."""
    text = _text_of(alert)
    return [tech for tech in TECHNIQUES if any(keyword in text for keyword in tech.keywords)]


def map_alerts(alerts: Iterable[Alert]) -> dict[str, list[Alert]]:
    """Group alerts by technique ID, preserving the alert order."""
    mapping: dict[str, list[Alert]] = {}
    for alert in alerts:
        for tech in match(alert):
            mapping.setdefault(tech.id, []).append(alert)
    return mapping


def technique_by_id(technique_id: str) -> Technique | None:
    return next((tech for tech in TECHNIQUES if tech.id == technique_id), None)
