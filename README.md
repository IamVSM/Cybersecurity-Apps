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
- **Offline breached pattern detection** using a bundled list of common leaked passwords.
- **Optional Have I Been Pwned (HIBP) lookup** via the k-anonymity API for dark web-style insights without sending full passwords.

### Quick Start

```bash
python -m password_strength_analyzer.cli --password "MyP@ssw0rd" --hibp
```

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
