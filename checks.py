# urljoin helps us safely combine a base URL with a path
# Example:
# base = https://example.com
# path = /swagger
# result = https://example.com/swagger
from urllib.parse import urljoin

# requests allows us to send HTTP requests to a website or API
import requests


# Timeout value for HTTP requests (seconds)
# This prevents the tool from hanging if a server is slow or unresponsive
TIMEOUT = 5


def make_finding(check: str, severity: str, title: str, evidence: str, recommendation: str) -> dict:
    """
    Helper function to create a standardized finding.

    Every security issue discovered by the scanner is stored
    using the same structure so the report is consistent.
    """

    return {
        "check": check,               # Name of the security check
        "severity": severity,         # Risk level (Low, Medium, High)
        "title": title,               # Short description of the issue
        "evidence": evidence,         # What we observed that triggered the finding
        "recommendation": recommendation  # Suggested fix
    }


def check_docs_endpoints(base_url: str) -> list:
    """
    Check for publicly exposed API documentation or operational endpoints.

    Many frameworks expose endpoints such as:
        /swagger
        /api-docs
        /openapi.json

    If these are publicly accessible, attackers can learn how the API works.
    """

    findings = []

    # Common documentation and monitoring endpoints
    # These are frequently exposed by default in many frameworks
    common_paths = [
        "/swagger",
        "/swagger/index.html",
        "/api-docs",
        "/openapi.json",
        "/swagger/v1/swagger.json",
        "/health",
        "/status",
        "/actuator/health",
        "/metrics"
    ]

    # Test each path
    for path in common_paths:

        # Build the full URL
        url = urljoin(base_url + "/", path.lstrip("/"))

        try:
            # Send request to the endpoint
            response = requests.get(url, timeout=TIMEOUT, allow_redirects=False)

            # If the endpoint exists (200 or redirect), it may be exposed
            if response.status_code in [200, 301, 302]:

                severity = "Medium"
                title = f"Potentially exposed endpoint found at {path}"

                # Some endpoints like /health or /metrics are operational
                # These are often less critical but still useful to attackers
                if any(keyword in path for keyword in ["health", "status", "metrics", "actuator"]):
                    severity = "Low"
                    title = f"Operational endpoint exposed at {path}"

                findings.append(
                    make_finding(
                        check="docs_endpoints",
                        severity=severity,
                        title=title,
                        evidence=f"{url} returned HTTP {response.status_code}",
                        recommendation="Restrict public access to non-essential documentation or operational endpoints."
                    )
                )

        # Ignore network errors and move to the next endpoint
        except requests.RequestException:
            continue

    return findings


def check_security_headers(base_url: str) -> list:
    """
    Check if important HTTP security headers are missing.

    Security headers help protect web applications from common attacks.
    """

    findings = []

    # Security headers that should normally be present
    required_headers = {
        "Strict-Transport-Security": "Add HSTS to enforce HTTPS connections.",
        "X-Content-Type-Options": "Add X-Content-Type-Options: nosniff to reduce MIME-type sniffing risk.",
        "X-Frame-Options": "Add X-Frame-Options to reduce clickjacking risk.",
        "Referrer-Policy": "Add a Referrer-Policy header to control referrer information leakage."
    }

    try:
        # Request the main page of the API
        response = requests.get(base_url, timeout=TIMEOUT)

        # Get response headers
        headers = response.headers

        # Check if required security headers exist
        for header, recommendation in required_headers.items():

            if header not in headers:

                findings.append(
                    make_finding(
                        check="security_headers",
                        severity="Low",
                        title=f"Missing security header: {header}",
                        evidence=f"{header} was not present in the response headers.",
                        recommendation=recommendation
                    )
                )

    except requests.RequestException as e:

        # If we cannot reach the server, record an error
        findings.append(
            make_finding(
                check="security_headers",
                severity="Medium",
                title="Unable to assess security headers",
                evidence=str(e),
                recommendation="Verify the target is reachable and returns a valid HTTP response."
            )
        )

    return findings


def check_cors_configuration(base_url: str) -> list:
    """
    Check if Cross-Origin Resource Sharing (CORS) is too permissive.

    If Access-Control-Allow-Origin is "*", any website can make requests
    to this API, which may create security risks.
    """

    findings = []

    # Simulate a request coming from another domain
    headers = {
        "Origin": "https://evil.example"
    }

    try:
        # Send an OPTIONS request to inspect CORS behavior
        response = requests.options(base_url, headers=headers, timeout=TIMEOUT)

        allow_origin = response.headers.get("Access-Control-Allow-Origin")
        allow_credentials = response.headers.get("Access-Control-Allow-Credentials")

        # If CORS allows all origins
        if allow_origin == "*":

            severity = "Medium"
            recommendation = "Avoid permissive wildcard CORS unless the API is explicitly intended for unrestricted public cross-origin access."

            # Allowing credentials with wildcard origins is a serious issue
            if allow_credentials and allow_credentials.lower() == "true":
                severity = "High"
                recommendation = "Do not combine credentialed requests with permissive CORS. Restrict allowed origins explicitly."

            findings.append(
                make_finding(
                    check="cors",
                    severity=severity,
                    title="Permissive CORS configuration detected",
                    evidence=f"Access-Control-Allow-Origin={allow_origin}, Access-Control-Allow-Credentials={allow_credentials}",
                    recommendation=recommendation
                )
            )

    except requests.RequestException as e:

        findings.append(
            make_finding(
                check="cors",
                severity="Medium",
                title="Unable to assess CORS configuration",
                evidence=str(e),
                recommendation="Verify the endpoint supports HTTP requests and is reachable."
            )
        )

    return findings


def check_error_leakage(base_url: str) -> list:
    """
    Check if the server exposes internal error messages.

    Attackers often trigger errors intentionally to reveal:
    - stack traces
    - framework names
    - database errors
    """

    findings = []

    # Request a path that should not exist
    test_url = urljoin(base_url + "/", "this-path-should-not-exist-12345")

    # Patterns that often appear in debug or stack trace messages
    error_patterns = [
        "traceback",
        "stack trace",
        "exception",
        "nullpointerexception",
        "sql syntax",
        "fatal error",
        "runtime error",
        "application error",
        "server error in '/' application",
        "at org.springframework",
        "at line",
        "debug"
    ]

    try:
        response = requests.get(test_url, timeout=TIMEOUT)

        # Convert body to lowercase to make searching easier
        body = response.text.lower()

        # Check if any suspicious error messages appear
        matched_patterns = [pattern for pattern in error_patterns if pattern in body]

        if matched_patterns:

            findings.append(
                make_finding(
                    check="error_leakage",
                    severity="Medium",
                    title="Possible error or debug information leakage detected",
                    evidence=f"{test_url} response contained: {', '.join(matched_patterns)}",
                    recommendation="Return generic error messages in production and suppress debug details."
                )
            )

    except requests.RequestException as e:

        findings.append(
            make_finding(
                check="error_leakage",
                severity="Medium",
                title="Unable to assess error leakage",
                evidence=str(e),
                recommendation="Verify the target is reachable and can be tested safely."
            )
        )

    return findings