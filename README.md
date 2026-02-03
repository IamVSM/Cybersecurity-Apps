# Cybersecurity-Apps

## AI-Based Phishing Email Detector

This project provides a lightweight phishing email detector that combines:
- **Heuristic signals** (suspicious keywords, spoofed sender hints, risky TLDs, URLs, etc.).
- **Optional ML scoring** using a TF-IDF + logistic regression model trained on bundled sample data.

If scikit-learn is not installed, the detector automatically falls back to heuristics only.

### Quick Start

```bash
python -m ai_phishing_detector.cli \
  --json '{"subject": "Verify your account", "sender": "security@paypa1.com", "body": "Click now to avoid suspension"}'
```

### Input Format

Provide JSON with the following fields:

```json
{
  "subject": "string",
  "sender": "string",
  "body": "string"
}
```

### Optional Dependency

For the ML model, install scikit-learn:

```bash
pip install scikit-learn
```

### Example Output

```json
{
  "label": "phishing",
  "score": 0.83,
  "reasons": [
    "Suspicious keywords: click, suspension, verify",
    "Contains URL(s)",
    "Model probability: 0.78"
  ]
}
```

## AI Password Strength Analyzer

This project provides a password risk analyzer that blends heuristic scoring with AI-inspired signals to flag risky patterns and offer safer alternatives. It includes:
- **Risk scoring** based on length, character variety, sequences, repetition, and common substitutions.
- **Offline breached pattern detection** using bundled leaked-password lists, including a RockYou-style list.
- **Optional Have I Been Pwned (HIBP) lookup** via the k-anonymity API for dark web-style insights without sending full passwords.

### Quick Start

```bash
python -m password_strength_analyzer.cli --password "MyP@ssw0rd" --hibp
```

### RockYou Dataset Notes

The repository includes a truncated `rockyou.txt` sample for offline matching. Replace
`password_strength_analyzer/data/rockyou.txt` with the latest RockYou dataset if you want
full coverage.

### Example Output

```json
{
  "password": "MyP@ssw0rd",
  "risk_score": 0.7,
  "label": "medium",
  "reasons": [
    "Shorter than recommended (12+ characters)",
    "Uses multiple character categories",
    "Uses predictable substitutions of common words",
    "Found in Have I Been Pwned password corpus"
  ],
  "suggestions": [
    "Harbor!82m",
    "Cobalt#47Q",
    "Orbit$19p"
  ],
  "breached_offline": true,
  "breached_online": true,
  "hibp_count": 4010
}
```

## AI-Powered Incident Response Assistant

This project provides a structured incident response assistant that converts a short incident
description into a triage-ready playbook. It includes:
- **Severity scoring** with rationale based on observed indicators.
- **IR steps** aligned to containment, eradication, and recovery.
- **Containment checklist** for fast defensive action.
- **Evidence collection guide** to preserve forensic artifacts.
- **Executive-ready context** on impact, communications, and detection gaps.

### Quick Start

```bash
python -m incident_response_assistant.cli \
  --json '{"incident": "Suspicious PowerShell execution"}'
```

### Example Output

```json
{
  "incident": "Suspicious PowerShell execution",
  "severity": "High",
  "severity_score": 0.65,
  "rationale": [
    "Indicator observed: powershell.",
    "Indicator observed: suspicious."
  ],
  "ir_steps": [
    "Confirm alert context and validate the triggering telemetry.",
    "Scope affected hosts, users, and time range using SIEM and EDR."
  ],
  "containment_checklist": [
    "Isolate affected endpoints from the network."
  ],
  "evidence_to_collect": [
    "PowerShell operational logs and script block logging output."
  ],
  "why_cisos_love_this": [
    "Cuts response time with structured playbooks",
    "Reduces human error through consistent checklists"
  ]
}
```
