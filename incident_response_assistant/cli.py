import argparse
import json
import sys

from incident_response_assistant.assistant import analyze_incident


def _read_input(args: argparse.Namespace) -> dict:
    if args.json:
        return json.loads(args.json)
    if args.file:
        return json.loads(args.file.read())
    if not sys.stdin.isatty():
        return json.loads(sys.stdin.read())
    raise ValueError("Provide --json, --file, or pipe JSON via stdin.")


def main() -> int:
    parser = argparse.ArgumentParser(description="AI-Powered Incident Response Assistant")
    parser.add_argument("--json", help="JSON payload with incident description")
    parser.add_argument("--file", type=argparse.FileType("r"), help="File containing JSON payload")
    args = parser.parse_args()

    payload = _read_input(args)
    description = payload.get("incident") or payload.get("description") or ""
    assessment = analyze_incident(description)
    output = assessment.to_dict()
    output["incident"] = description
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
