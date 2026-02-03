import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
import importlib.util

DATA_PATH = Path(__file__).resolve().parent / "data" / "sample_emails.json"
SUSPICIOUS_KEYWORDS = {
    "urgent",
    "verify",
    "password",
    "login",
    "suspend",
    "suspension",
    "invoice",
    "payment",
    "immediately",
    "click",
    "upgrade",
    "over quota",
    "confirm",
    "wire",
    "gift card",
}

SUSPICIOUS_TLDS = {".zip", ".ru", ".tk", ".xyz"}


@dataclass
class DetectionResult:
    label: str
    score: float
    reasons: list[str]


@dataclass
class EmailSample:
    label: str
    subject: str
    sender: str
    body: str


class PhishingDetector:
    def __init__(self, threshold: float = 0.6) -> None:
        self.threshold = threshold
        self.model = self._build_model()
        self.vectorizer = None

    def _build_model(self):
        if not _sklearn_available():
            return None
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression

        samples = _load_samples(DATA_PATH)
        texts = [_combine_text(sample) for sample in samples]
        labels = [1 if sample.label == "phishing" else 0 for sample in samples]

        vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
        features = vectorizer.fit_transform(texts)
        model = LogisticRegression(max_iter=500)
        model.fit(features, labels)
        self.vectorizer = vectorizer
        return model

    def score_email(self, subject: str, sender: str, body: str) -> DetectionResult:
        reasons: list[str] = []
        heuristic_score = _heuristic_score(subject, sender, body, reasons)

        model_score = 0.0
        if self.model and self.vectorizer:
            combined = _combine_text(EmailSample("unknown", subject, sender, body))
            features = self.vectorizer.transform([combined])
            model_score = float(self.model.predict_proba(features)[0][1])
            reasons.append(f"Model probability: {model_score:.2f}")

        final_score = _blend_scores(heuristic_score, model_score)
        label = "phishing" if final_score >= self.threshold else "legitimate"
        return DetectionResult(label=label, score=final_score, reasons=reasons)


def _load_samples(path: Path) -> list[EmailSample]:
    raw = json.loads(path.read_text())
    return [
        EmailSample(
            label=entry["label"],
            subject=entry["subject"],
            sender=entry["sender"],
            body=entry["body"],
        )
        for entry in raw
    ]


def _combine_text(sample: EmailSample) -> str:
    return f"{sample.subject}\n{sample.sender}\n{sample.body}"


def _heuristic_score(subject: str, sender: str, body: str, reasons: list[str]) -> float:
    content = f"{subject} {body}".lower()
    sender_lower = sender.lower()
    score = 0.0

    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in content]
    if keyword_hits:
        score += 0.25 + 0.03 * len(keyword_hits)
        reasons.append(f"Suspicious keywords: {', '.join(sorted(keyword_hits))}")

    url_matches = re.findall(r"https?://[^\s]+", body)
    if url_matches:
        score += 0.2
        reasons.append("Contains URL(s)")
        if any(_url_has_suspicious_tld(url) for url in url_matches):
            score += 0.15
            reasons.append("Suspicious TLD detected")

    if re.search(r"\b\d{4,}\b", body):
        score += 0.1
        reasons.append("Contains long numeric sequence")

    if _looks_like_spoofed_sender(sender_lower):
        score += 0.2
        reasons.append("Sender domain looks spoofed")

    if "@" in sender_lower and sender_lower.split("@", 1)[1].count("-") >= 3:
        score += 0.1
        reasons.append("Sender domain has excessive hyphens")

    normalized_score = min(score, 1.0)
    return normalized_score


def _url_has_suspicious_tld(url: str) -> bool:
    return any(url.endswith(tld) for tld in SUSPICIOUS_TLDS)


def _looks_like_spoofed_sender(sender: str) -> bool:
    if "@" not in sender:
        return False
    domain = sender.split("@", 1)[1]
    return any(char.isdigit() for char in domain)


def _blend_scores(heuristic_score: float, model_score: float) -> float:
    if model_score <= 0:
        return heuristic_score
    return _sigmoid(0.65 * model_score + 0.35 * heuristic_score)


def _sigmoid(value: float) -> float:
    return 1 / (1 + math.exp(-4 * (value - 0.5)))


def _sklearn_available() -> bool:
    return importlib.util.find_spec("sklearn") is not None
