import argparse
import json
import sys
import os
from shieldscan.scanner import SecretScanner

def main():
    parser = argparse.ArgumentParser(
        prog="shieldscan",
        description="Shield Scan: Local security scanner for detecting exposed secrets and high-entropy strings."
    )
    parser.add_argument(
        "target",
        type=str,
        help="Path to a file or directory to scan."
    )
    parser.add_argument(
        "-e", "--entropy",
        type=float,
        default=4.5,
        help="Shannon entropy threshold (default: 4.5)."
    )
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json"],
        default="text",
        help="Output format: 'text' (default) or 'json'."
    )

    args = parser.parse_args()

    scanner = SecretScanner(entropy_threshold=args.entropy)

    if os.path.isdir(args.target):
        findings = scanner.scan_directory(args.target)
    elif os.path.isfile(args.target):
        findings = scanner.scan_file(args.target)
    else:
        print(f"Error: Target path '{args.target}' does not exist.", file=sys.stderr)
        sys.exit(1)

    if args.format == "json":
        print(json.dumps(findings, indent=2))
    else:
        if not findings:
            print("Scan completed: No secrets or high-entropy tokens detected.")
        else:
            print(f"Scan completed: Found {len(findings)} potential finding(s):\n")
            for item in findings:
                print(f" Source: {item.get('source')}")
                print(f" Line:   {item.get('line')}")
                print(f" Type:   {item.get('type')}")
                print(f" Match:  {item.get('match')}")
                print(f" Reason: {item.get('reason')}")
                print("-" * 40)

    if findings:
        sys.exit(1)

if __name__ == "__main__":
    main()