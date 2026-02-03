from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class IncidentAssessment:
    severity: str
    severity_score: float
    rationale: list[str]
    ir_steps: list[str]
    containment_checklist: list[str]
    evidence_to_collect: list[str]
    impact_considerations: list[str]
    communication_notes: list[str]
    detection_opportunities: list[str]
    ciso_value: list[str]

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "severity_score": round(self.severity_score, 2),
            "rationale": self.rationale,
            "ir_steps": self.ir_steps,
            "containment_checklist": self.containment_checklist,
            "evidence_to_collect": self.evidence_to_collect,
            "impact_considerations": self.impact_considerations,
            "communication_notes": self.communication_notes,
            "detection_opportunities": self.detection_opportunities,
            "why_cisos_love_this": self.ciso_value,
        }


KEYWORD_WEIGHTS = {
    "ransomware": 0.45,
    "data exfil": 0.4,
    "exfiltration": 0.4,
    "privilege escalation": 0.25,
    "lateral movement": 0.3,
    "command and control": 0.3,
    "c2": 0.3,
    "persistence": 0.2,
    "credential dumping": 0.35,
    "powershell": 0.2,
    "script block": 0.15,
    "phishing": 0.15,
    "malware": 0.25,
    "suspicious": 0.1,
}

CATEGORY_HINTS = {
    "powershell": "PowerShell",
    "credential": "Credential Access",
    "ransomware": "Ransomware",
    "exfil": "Data Exfiltration",
    "phishing": "Phishing",
    "malware": "Malware",
}


def analyze_incident(description: str) -> IncidentAssessment:
    normalized = description.lower().strip()
    keywords = _collect_keywords(normalized)
    severity_score = _score_severity(keywords)
    severity = _severity_label(severity_score)

    rationale = _build_rationale(keywords)
    categories = _detect_categories(normalized)

    ir_steps = _build_ir_steps(categories)
    containment_checklist = _build_containment(categories)
    evidence = _build_evidence(categories)
    impact = _build_impact(categories)
    communication = _build_communication(severity)
    detections = _build_detections(categories)
    ciso_value = [
        "Cuts response time with structured playbooks",
        "Reduces human error through consistent checklists",
    ]

    return IncidentAssessment(
        severity=severity,
        severity_score=severity_score,
        rationale=rationale,
        ir_steps=ir_steps,
        containment_checklist=containment_checklist,
        evidence_to_collect=evidence,
        impact_considerations=impact,
        communication_notes=communication,
        detection_opportunities=detections,
        ciso_value=ciso_value,
    )


def _collect_keywords(text: str) -> list[str]:
    matches = []
    for keyword in KEYWORD_WEIGHTS:
        if keyword in text:
            matches.append(keyword)
    return matches


def _score_severity(keywords: Iterable[str]) -> float:
    score = 0.35
    for keyword in keywords:
        score += KEYWORD_WEIGHTS.get(keyword, 0)
    return min(score, 0.99)


def _severity_label(score: float) -> str:
    if score >= 0.85:
        return "Critical"
    if score >= 0.6:
        return "High"
    if score >= 0.45:
        return "Medium"
    return "Low"


def _build_rationale(keywords: list[str]) -> list[str]:
    if not keywords:
        return ["Baseline severity applied due to limited indicators."]
    return [f"Indicator observed: {keyword}." for keyword in keywords]


def _detect_categories(text: str) -> set[str]:
    categories = set()
    if "powershell" in text or "script block" in text:
        categories.add("powershell")
    if "credential" in text or "hash" in text:
        categories.add("credential")
    if "ransomware" in text or "encrypt" in text:
        categories.add("ransomware")
    if "exfil" in text or "data leak" in text:
        categories.add("exfil")
    if "phishing" in text or "spoof" in text:
        categories.add("phishing")
    if "malware" in text or "payload" in text:
        categories.add("malware")
    return categories


def _build_ir_steps(categories: set[str]) -> list[str]:
    steps = [
        "Confirm alert context and validate the triggering telemetry.",
        "Scope affected hosts, users, and time range using SIEM and EDR.",
        "Prioritize assets based on business criticality and exposure.",
        "Contain the threat while preserving forensic integrity.",
        "Eradicate malicious artifacts and close exploited gaps.",
        "Recover systems and monitor for re-infection.",
        "Document lessons learned and update detections/playbooks.",
    ]
    if "powershell" in categories:
        steps.insert(2, "Review PowerShell command lines, script blocks, and encoded payloads.")
    if "credential" in categories:
        steps.insert(3, "Check for credential theft indicators and reset exposed accounts.")
    if "ransomware" in categories:
        steps.insert(4, "Validate backup integrity and isolate encrypted systems.")
    if "exfil" in categories:
        steps.insert(4, "Identify data staging locations and outbound transfer paths.")
    return steps


def _build_containment(categories: set[str]) -> list[str]:
    checklist = [
        "Isolate affected endpoints from the network.",
        "Disable compromised accounts or tokens.",
        "Block known malicious IPs/domains at the firewall and proxy.",
        "Preserve volatile data before powering off systems.",
        "Coordinate containment with IT change management.",
    ]
    if "powershell" in categories:
        checklist.append("Apply PowerShell constrained language mode where feasible.")
    if "credential" in categories:
        checklist.append("Enforce MFA re-registration and rotate privileged credentials.")
    if "ransomware" in categories:
        checklist.append("Suspend backup jobs to prevent contaminated backups.")
    if "exfil" in categories:
        checklist.append("Throttle or block suspicious outbound data transfer channels.")
    return checklist


def _build_evidence(categories: set[str]) -> list[str]:
    evidence = [
        "EDR telemetry and process tree exports.",
        "Authentication logs (SSO, VPN, AD).",
        "Network flows and proxy logs for the incident window.",
        "Disk and memory captures for impacted hosts.",
    ]
    if "powershell" in categories:
        evidence.extend(
            [
                "PowerShell operational logs and script block logging output.",
                "AMSI logs and encoded command samples.",
            ]
        )
    if "credential" in categories:
        evidence.append("LSASS access events and credential dumping artifacts.")
    if "ransomware" in categories:
        evidence.append("File modification timelines and ransom notes (if any).")
    if "exfil" in categories:
        evidence.append("Data access logs for sensitive repositories.")
    return evidence


def _build_impact(categories: set[str]) -> list[str]:
    impact = [
        "Business operations disrupted by endpoint isolation.",
        "Potential lateral movement across shared services.",
        "Regulatory exposure if sensitive data is impacted.",
    ]
    if "ransomware" in categories:
        impact.append("Risk of data availability loss and downtime escalation.")
    if "exfil" in categories:
        impact.append("Potential data disclosure notification obligations.")
    return impact


def _build_communication(severity: str) -> list[str]:
    notes = [
        "Notify SOC leadership and incident commander immediately.",
        "Log all containment actions with timestamps for auditability.",
    ]
    if severity in {"High", "Critical"}:
        notes.append("Prepare executive briefings and legal/privacy notifications.")
    return notes


def _build_detections(categories: set[str]) -> list[str]:
    detections = [
        "Hunt for similar behaviors across endpoints using EDR queries.",
        "Enable alerting for anomalous authentication patterns.",
    ]
    if "powershell" in categories:
        detections.append("Create detections for encoded PowerShell and LOLBins usage.")
    if "ransomware" in categories:
        detections.append("Alert on mass file renames or rapid encryption activity.")
    if "exfil" in categories:
        detections.append("Alert on high-volume outbound transfers or unusual cloud sync.")
    return detections


def summarize_categories(categories: set[str]) -> list[str]:
    if not categories:
        return ["General Incident"]
    return [CATEGORY_HINTS[category] for category in categories if category in CATEGORY_HINTS]
