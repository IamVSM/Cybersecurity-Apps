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
