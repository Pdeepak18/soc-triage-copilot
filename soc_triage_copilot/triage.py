"""Deterministic triage engine.

Everything here runs offline and gives the same answer twice. The LLM layer
(``llm.py``) only rewrites this structured output into prose - it never decides
the verdict. That separation is what makes the tool safe to run on real cases:
no case data leaves the machine unless an analyst explicitly asks for an LLM.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime

from . import attack
from .models import Alert, Case

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b")
USER_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b")

FILE_EXTENSIONS = {"exe", "dll", "ps1", "js", "vbs", "docm", "xlsm", "iso", "lnk", "hta"}

ENTITY_KEYS = {
    "ip": "ip", "ipaddress": "ip", "remoteip": "ip", "sourceip": "ip",
    "host": "host", "hostname": "host", "devicename": "host", "computer": "host",
    "user": "user", "account": "user", "username": "user", "userprincipalname": "user",
    "hash": "hash", "sha256": "hash", "filehash": "hash", "md5": "hash",
    "file": "file", "filename": "file", "process": "file", "url": "url", "domain": "domain",
}

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str
    evidence: list[str]
    recommendation: str

    def as_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique": self.technique_name,
            "tactic": self.tactic,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass
class TriageResult:
    case_id: str
    verdict: str
    severity: str
    risk_score: int
    confidence: str
    findings: list[Finding] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    timeline: list[dict] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    summary: str = ""

    def as_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "verdict": self.verdict,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "summary": self.summary,
            "findings": [f.as_dict() for f in self.findings],
            "iocs": self.iocs,
            "timeline": self.timeline,
            "next_steps": self.next_steps,
        }


def _entity(kind: str, value: str) -> tuple[str, str] | None:
    value = value.strip()
    if not value:
        return None
    return kind, value


def collect_iocs(alerts: list[Alert]) -> dict[str, list[str]]:
    iocs: dict[str, set[str]] = {"ip": set(), "host": set(), "user": set(),
                                 "hash": set(), "file": set(), "url": set(), "domain": set()}

    for alert in alerts:
        for key, raw in alert.entities.items():
            normalised_key = ENTITY_KEYS.get(key.lower().replace("_", ""), None)
            values = raw if isinstance(raw, (list, tuple, set)) else [raw]
            for value in values:
                if value is None:
                    continue
                text = str(value).strip()
                if normalised_key:
                    iocs[normalised_key].add(text)
                    continue
                _scan_text(text, iocs)

        _scan_text(f"{alert.rule} {alert.description}", iocs)

    # Any email address is also a user indicator; any bare domain a domain IOC.
    for user in list(iocs["user"]):
        if "@" in user:
            domain = user.split("@", 1)[1].lower()
            if domain not in {"microsoft.com", "windows.com", "office.com"}:
                iocs["domain"].add(domain)

    cleaned: dict[str, list[str]] = {}
    for key, values in iocs.items():
        filtered = {v for v in values if v and not _is_noise(key, v)}
        if filtered:
            cleaned[key] = sorted(filtered)
    return cleaned


def _scan_text(text: str, iocs: dict[str, set[str]]) -> None:
    for match in IP_RE.findall(text):
        try:
            ipaddress.ip_address(match)
        except ValueError:
            continue
        iocs["ip"].add(match)
    for match in HASH_RE.findall(text):
        iocs["hash"].add(match.lower())
    for match in USER_RE.findall(text):
        iocs["user"].add(match.lower())
    for match in DOMAIN_RE.findall(text):
        tld = match.rsplit(".", 1)[-1].lower()
        if tld in FILE_EXTENSIONS:
            continue
        iocs["domain"].add(match.lower())


def _is_noise(kind: str, value: str) -> bool:
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return True
        return ip.is_loopback or ip.is_link_local
    if kind == "domain":
        return value.lower() in {"microsoft.com", "windows.com", "office.com", "localhost"}
    return False


def _confidence(alerts: list[Alert], findings: list[Finding]) -> str:
    if len(findings) >= 3 and len(alerts) >= 3:
        return "high"
    if len(findings) >= 2:
        return "medium"
    if findings:
        return "low"
    return "low"


def _risk(alerts: list[Alert], findings: list[Finding]) -> int:
    base = {"informational": 5, "low": 15, "medium": 35, "high": 55, "critical": 75}
    highest = max((SEVERITY_RANK.get(a.severity, 2) for a in alerts), default=0)
    score = base.get(["informational", "low", "medium", "high", "critical"][highest], 20)
    if any(attack.technique_by_id(f.technique_id) and attack.technique_by_id(f.technique_id).critical for f in findings):
        score += 15
    score += min(15, 5 * max(0, len(findings) - 1))
    return min(100, score)


def _verdict(score: int, findings: list[Finding]) -> str:
    critical_chain = sum(
        1 for f in findings
        if attack.technique_by_id(f.technique_id) and attack.technique_by_id(f.technique_id).critical
    )
    if score >= 75 or critical_chain >= 2:
        return "likely_true_positive"
    if score >= 40:
        return "needs_review"
    return "likely_false_positive"


def triage(case: Case) -> TriageResult:
    if not case.alerts:
        return TriageResult(
            case_id=case.id,
            verdict="needs_review",
            severity="informational",
            risk_score=0,
            confidence="low",
            summary="Case contains no alerts. Ask the source system to resend the event.",
        )

    mapping = attack.map_alerts(case.alerts)
    findings: list[Finding] = []
    for technique_id, alerts in mapping.items():
        tech = attack.technique_by_id(technique_id)
        if tech is None:
            continue
        findings.append(
            Finding(
                technique_id=tech.id,
                technique_name=tech.name,
                tactic=tech.tactic,
                confidence="high" if len(alerts) > 1 else "medium",
                evidence=[f"{a.rule} @ {a.timestamp:%H:%M:%S}" for a in alerts],
                recommendation=tech.recommendation,
            )
        )
    findings.sort(key=lambda f: (f.tactic, f.technique_id))

    iocs = collect_iocs(case.alerts)
    score = _risk(case.alerts, findings)
    result = TriageResult(
        case_id=case.id,
        verdict=_verdict(score, findings),
        severity=case.highest_severity,
        risk_score=score,
        confidence=_confidence(case.alerts, findings),
        findings=findings,
        iocs=iocs,
        timeline=[
            {
                "time": alert.timestamp.isoformat(),
                "rule": alert.rule,
                "severity": alert.severity,
                "summary": alert.description or alert.rule,
            }
            for alert in sorted(case.alerts, key=lambda a: a.timestamp)
        ],
        next_steps=_next_steps(case, findings, iocs),
        summary=_summary(case, findings, iocs, score),
    )
    return result


def _next_steps(case: Case, findings: list[Finding], iocs: dict[str, list[str]]) -> list[str]:
    steps: list[str] = []
    for finding in findings:
        if finding.recommendation and finding.recommendation not in steps:
            steps.append(finding.recommendation)

    if iocs.get("host"):
        steps.append(
            f"Contain affected host(s): {', '.join(iocs['host'][:3])} - isolate from the network before eradication."
        )
    if iocs.get("user"):
        steps.append(
            f"Verify account activity for {', '.join(iocs['user'][:3])} and revoke active sessions if suspicious."
        )

    public_ips, internal_ips = [], []
    for value in iocs.get("ip", []):
        try:
            (internal_ips if ipaddress.ip_address(value).is_private else public_ips).append(value)
        except ValueError:
            continue
    if public_ips:
        steps.append(
            f"Block or sinkhole the external indicators {', '.join(public_ips[:3])} at the perimeter, "
            f"then hunt the proxy logs."
        )
    if internal_ips:
        steps.append(
            f"Pivot on internal address(es) {', '.join(internal_ips[:3])}: check which other hosts "
            f"communicated with them in the last 24 hours."
        )
    steps.append("Document the timeline and attach the alert export to the ticket before closing.")
    return steps


def _summary(case: Case, findings: list[Finding], iocs: dict[str, list[str]], score: int) -> str:
    tactics = sorted({f.tactic for f in findings})
    parts = [
        f"Case {case.id} ('{case.title}') contains {len(case.alerts)} alert(s) from {case.source}.",
        f"Highest alert severity is {case.highest_severity} and the derived risk score is {score}/100.",
    ]
    if findings:
        parts.append(
            f"{len(findings)} ATT&CK technique(s) matched across {len(tactics)} tactic(s): "
            f"{', '.join(tactics)}."
        )
    else:
        parts.append("No ATT&CK technique matched the alert text, so the case is unclassified.")
    if iocs:
        counts = ", ".join(f"{len(values)} {key}" for key, values in sorted(iocs.items()))
        parts.append(f"Indicators extracted: {counts}.")
    return " ".join(parts)
