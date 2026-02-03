import argparse
import json
import sys

from .detector import PhishingDetector


def _read_input(args: argparse.Namespace) -> dict:
    if args.json:
        return json.loads(args.json)
    if args.file:
        return json.loads(args.file.read())
    if not sys.stdin.isatty():
        return json.loads(sys.stdin.read())
    raise ValueError("Provide --json, --file, or pipe JSON via stdin.")


def main() -> int:
    parser = argparse.ArgumentParser(description="AI-Based Phishing Email Detector")
    parser.add_argument("--json", help="JSON payload with subject, sender, body fields")
    parser.add_argument("--file", type=argparse.FileType("r"), help="File containing JSON payload")
    parser.add_argument("--threshold", type=float, default=0.6, help="Score threshold")
    args = parser.parse_args()

    payload = _read_input(args)
    detector = PhishingDetector(threshold=args.threshold)
    result = detector.score_email(
        subject=payload.get("subject", ""),
        sender=payload.get("sender", ""),
        body=payload.get("body", ""),
    )

    output = {
        "label": result.label,
        "score": round(result.score, 3),
        "reasons": result.reasons,
    }
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
