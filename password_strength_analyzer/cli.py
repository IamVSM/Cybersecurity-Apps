import argparse
import getpass

from password_strength_analyzer.analyzer import assess_password, assessment_to_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI-assisted password strength analyzer")
    parser.add_argument("--password", help="Password to analyze (discouraged on shared systems)")
    parser.add_argument(
        "--hibp",
        action="store_true",
        help="Check password against Have I Been Pwned k-anonymity API",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    password = args.password
    if password is None:
        password = getpass.getpass("Enter password to analyze: ")

    assessment = assess_password(password=password, include_hibp=args.hibp)
    print(assessment_to_json(assessment))


if __name__ == "__main__":
    main()
