from __future__ import annotations

import dataclasses
import hashlib
import json
import secrets
import string
import urllib.error
import urllib.request
from pathlib import Path
from typing import List

DATA_DIR = Path(__file__).resolve().parent / "data"
BREACHED_LIST_PATHS = (
    DATA_DIR / "breached_passwords.txt",
    DATA_DIR / "rockyou.txt",
)


@dataclasses.dataclass
class PasswordAssessment:
    password: str
    risk_score: float
    label: str
    reasons: List[str]
    suggestions: List[str]
    breached_offline: bool
    breached_online: bool | None
    hibp_count: int | None


def _load_breached_passwords() -> set[str]:
    breached: set[str] = set()
    for path in BREACHED_LIST_PATHS:
        if not path.exists():
            continue
        breached.update(
            line.strip().lower()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        )
    return breached


def _contains_sequence(password: str) -> bool:
    sequences = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    ]
    for seq in sequences:
        for i in range(len(seq) - 2):
            chunk = seq[i : i + 3]
            if chunk in password:
                return True
    return False


def _contains_repetition(password: str) -> bool:
    if len(set(password)) <= max(1, len(password) // 4):
        return True
    for char in set(password):
        if char * 3 in password:
            return True
    return False


def _check_substitutions(password: str) -> bool:
    substitutions = {
        "@": "a",
        "0": "o",
        "1": "l",
        "3": "e",
        "$": "s",
        "!": "i",
    }
    normalized = "".join(substitutions.get(c, c) for c in password.lower())
    common_words = {"password", "admin", "welcome", "dragon", "football", "monkey"}
    return any(word in normalized for word in common_words)


def _format_risk_label(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


def _generate_suggestions(password: str, count: int = 3) -> List[str]:
    words = ["orbit", "cobalt", "harbor", "falcon", "ember", "sage", "vivid"]
    suggestions = []
    for _ in range(count):
        word = secrets.choice(words)
        suffix = secrets.choice(string.digits) + secrets.choice(string.digits)
        symbol = secrets.choice("!@#$%")
        mixed = word.capitalize() + symbol + suffix + secrets.choice(string.ascii_letters)
        suggestions.append(mixed)
    if not suggestions:
        suggestions.append(password)
    return suggestions


def _offline_breach_match(password: str, breached_set: set[str]) -> bool:
    normalized = password.strip().lower()
    if normalized in breached_set:
        return True
    for entry in breached_set:
        if entry and entry in normalized:
            return True
    return False


def _hibp_lookup(password: str, timeout: float = 5.0) -> tuple[bool, int | None]:
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    request = urllib.request.Request(url, headers={"User-Agent": "PasswordStrengthAnalyzer"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, urllib.error.HTTPError):
        return False, None
    for line in body.splitlines():
        if not line:
            continue
        candidate_suffix, count = line.split(":")
        if candidate_suffix.strip().upper() == suffix:
            return True, int(count.strip())
    return False, 0


def assess_password(password: str, include_hibp: bool = False) -> PasswordAssessment:
    if not password:
        raise ValueError("Password must be provided")

    breached_set = _load_breached_passwords()
    breached_offline = _offline_breach_match(password, breached_set)

    reasons: List[str] = []
    score = 0.0

    length = len(password)
    if length < 8:
        score += 0.4
        reasons.append("Too short (under 8 characters)")
    elif length < 12:
        score += 0.2
        reasons.append("Shorter than recommended (12+ characters)")
    else:
        reasons.append("Length meets recommended minimum")

    categories = sum(
        [
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(c in string.punctuation for c in password),
        ]
    )
    if categories <= 2:
        score += 0.2
        reasons.append("Limited character variety")
    else:
        reasons.append("Uses multiple character categories")

    if _contains_sequence(password.lower()):
        score += 0.15
        reasons.append("Contains sequential or keyboard patterns")

    if _contains_repetition(password):
        score += 0.15
        reasons.append("Contains repeated characters or low entropy")

    if _check_substitutions(password):
        score += 0.15
        reasons.append("Uses predictable substitutions of common words")

    if breached_offline:
        score += 0.3
        reasons.append("Matches an offline breached password pattern")

    breached_online = None
    hibp_count = None
    if include_hibp:
        breached_online, hibp_count = _hibp_lookup(password)
        if breached_online:
            score += 0.35
            reasons.append("Found in Have I Been Pwned password corpus")
        elif breached_online is False and hibp_count == 0:
            reasons.append("Not found in Have I Been Pwned password corpus")
        else:
            reasons.append("Have I Been Pwned lookup unavailable")

    score = min(score, 1.0)
    label = _format_risk_label(score)

    suggestions = _generate_suggestions(password)

    return PasswordAssessment(
        password=password,
        risk_score=score,
        label=label,
        reasons=reasons,
        suggestions=suggestions,
        breached_offline=breached_offline,
        breached_online=breached_online,
        hibp_count=hibp_count,
    )


def assessment_to_json(assessment: PasswordAssessment) -> str:
    return json.dumps(dataclasses.asdict(assessment), indent=2)


__all__ = ["assess_password", "assessment_to_json", "PasswordAssessment"]
