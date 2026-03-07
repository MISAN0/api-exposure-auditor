# argparse allows us to read arguments from the command line
# Example: python scanner.py https://example.com
import argparse

# json is used to save the scan results in a JSON report file
import json

# sys is a system module (not heavily used here but commonly included for CLI tools)
import sys

# urlparse helps us break down a URL and check if it has http/https
from urllib.parse import urlparse

# requests is used to send HTTP requests to the target website/API
import requests

# datetime is used to record when the scan was performed
from datetime import datetime


# These functions are imported from checks.py
# Each function performs a different security check
from checks import (
    check_docs_endpoints,      # Looks for exposed API documentation endpoints
    check_security_headers,    # Checks if important security headers are missing
    check_cors_configuration,  # Checks if CORS is misconfigured
    check_error_leakage        # Checks if error messages expose sensitive info
)


def normalize_url(url: str) -> str:
    """
    Ensure the URL has a scheme (http or https).

    Users might enter:
        example.com

    But requests needs:
        https://example.com
    """

    # Break the URL into parts
    parsed = urlparse(url)

    # If the user did not include http/https, we add https by default
    if not parsed.scheme:
        url = "https://" + url

    # Remove a trailing slash so URLs are consistent
    return url.rstrip("/")


def run_checks(target_url: str):
    """
    Run all security checks against the target API.

    Each check function returns a list of findings.
    We combine all findings into a single list.
    """

    findings = []

    try:
        # Check if common API documentation endpoints are exposed
        findings.extend(check_docs_endpoints(target_url))

        # Check if security headers are missing
        findings.extend(check_security_headers(target_url))

        # Check if the API allows unsafe cross-origin requests
        findings.extend(check_cors_configuration(target_url))

        # Check if the server leaks internal error messages
        findings.extend(check_error_leakage(target_url))

    # If the website cannot be reached, we record a connection error
    except requests.exceptions.RequestException as e:
        findings.append({
            "check": "connection",
            "severity": "High",
            "title": "Connection error",
            "evidence": str(e),
            "recommendation": "Verify the target URL and network connectivity."
        })

    return findings


def print_summary(findings):
    """
    Print the scan results in the terminal.
    """

    # If no problems were found
    if not findings:
        print("\n[OK] No major exposure issues detected.")
        return

    print("\nFindings:\n")

    # Loop through every finding and display it
    for finding in findings:

        severity = finding["severity"]
        title = finding["title"]
        evidence = finding["evidence"]

        print(f"[{severity}] {title}")
        print(f" Evidence: {evidence}\n")


def print_severity_summary(findings):
    """
    Count how many findings exist for each severity level.
    This gives a quick overview of scan results.
    """

    high = 0
    medium = 0
    low = 0

    for finding in findings:
        if finding["severity"] == "High":
            high += 1
        elif finding["severity"] == "Medium":
            medium += 1
        elif finding["severity"] == "Low":
            low += 1

    print("Scan Summary")
    print("------------")
    print(f"High: {high}")
    print(f"Medium: {medium}")
    print(f"Low: {low}\n")


def save_report(findings, filename="report.json"):
    """
    Save all findings to a JSON file.
    The report also includes when the scan was performed.
    """

    report_data = {
        "scan_time": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }

    # Write the report to a JSON file
    with open(filename, "w") as f:
        json.dump(report_data, f, indent=4)

    print(f"\nReport saved to {filename}")


def main():
    """
    Main entry point of the program.
    Handles command line arguments and runs the scan.
    """

    # Create a command line argument parser
    parser = argparse.ArgumentParser(
        description="API Exposure Auditor - defensive API security auditing tool"
    )

    # Required argument: the target API URL
    parser.add_argument(
        "url",
        help="Base URL of the target API (example: https://example.com)"
    )

    # Optional argument: output file name
    parser.add_argument(
        "--output",
        default="report.json",
        help="Output JSON report filename"
    )

    # Parse arguments provided by the user
    args = parser.parse_args()

    # Clean and normalize the URL
    target_url = normalize_url(args.url)

    # Display basic scan information
    print("\nAPI Exposure Auditor")
    print("--------------------")
    print(f"Target: {target_url}\n")

    # Run the security checks
    findings = run_checks(target_url)

    # Print detailed findings
    print_summary(findings)

    # Print quick severity overview
    print_severity_summary(findings)

    # Save results to a JSON report
    save_report(findings, args.output)


# This ensures main() runs only when the script is executed directly
# and not when imported as a module
if __name__ == "__main__":
    main()