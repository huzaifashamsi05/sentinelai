"""
OWASP Top 10-style checks against a target. Pure passive/read-only HTTP
checks (no exploit payloads fired) — appropriate for a student security
scanner. Checks are informational: missing headers, cookie flags, server
banner disclosure, outdated-looking library versions in page source.
"""
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests


@dataclass
class Finding:
    check: str
    risk: str  # Low / Medium / High
    detail: str
    owasp_category: str


SECURITY_HEADERS = {
    "Content-Security-Policy": ("Medium", "A05:2021 Security Misconfiguration"),
    "X-Content-Type-Options": ("Low", "A05:2021 Security Misconfiguration"),
    "X-Frame-Options": ("Medium", "A05:2021 Security Misconfiguration"),
    "Strict-Transport-Security": ("Medium", "A02:2021 Cryptographic Failures"),
    "Referrer-Policy": ("Low", "A05:2021 Security Misconfiguration"),
}

# Deliberately vague version patterns — purely to flag "a version string is
# exposed", not to fingerprint real CVEs. Matches the educational scope of
# this check.
OUTDATED_HINTS = [
    (re.compile(r"jquery[-.](1\.[0-9]|2\.[0-2])", re.I), "jQuery version in page source looks old"),
    (re.compile(r"bootstrap[-.](2\.|3\.[0-3])", re.I), "Bootstrap version in page source looks old"),
]


def check_security_headers(resp: requests.Response) -> list[Finding]:
    findings = []
    for header, (risk, category) in SECURITY_HEADERS.items():
        if header not in resp.headers:
            findings.append(Finding(
                check=f"missing_header:{header}",
                risk=risk,
                detail=f"Response is missing the '{header}' header.",
                owasp_category=category,
            ))
    return findings


def check_server_banner(resp: requests.Response) -> list[Finding]:
    findings = []
    server = resp.headers.get("Server")
    if server:
        findings.append(Finding(
            check="server_banner_disclosure",
            risk="Low",
            detail=f"Server header discloses: '{server}'",
            owasp_category="A05:2021 Security Misconfiguration",
        ))
    powered_by = resp.headers.get("X-Powered-By")
    if powered_by:
        findings.append(Finding(
            check="x_powered_by_disclosure",
            risk="Low",
            detail=f"X-Powered-By header discloses: '{powered_by}'",
            owasp_category="A05:2021 Security Misconfiguration",
        ))
    return findings


def check_cookie_flags(resp: requests.Response) -> list[Finding]:
    findings = []
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie._rest).lower():
            issues.append("missing HttpOnly flag")
        if issues:
            findings.append(Finding(
                check=f"cookie_flags:{cookie.name}",
                risk="Medium",
                detail=f"Cookie '{cookie.name}' is {', '.join(issues)}.",
                owasp_category="A05:2021 Security Misconfiguration",
            ))
    return findings


def check_outdated_libraries(resp: requests.Response) -> list[Finding]:
    findings = []
    body = resp.text[:200_000]  # cap — don't scan megabytes of HTML
    for pattern, message in OUTDATED_HINTS:
        if pattern.search(body):
            findings.append(Finding(
                check="outdated_library_hint",
                risk="Medium",
                detail=message,
                owasp_category="A06:2021 Vulnerable and Outdated Components",
            ))
    return findings


def check_https(url: str, resp: requests.Response) -> list[Finding]:
    findings = []
    if urlparse(url).scheme != "https":
        findings.append(Finding(
            check="no_https",
            risk="High",
            detail="Site is served over plain HTTP, not HTTPS.",
            owasp_category="A02:2021 Cryptographic Failures",
        ))
    return findings


def run_all_checks(url: str, resp: requests.Response) -> list[Finding]:
    findings: list[Finding] = []
    findings += check_https(url, resp)
    findings += check_security_headers(resp)
    findings += check_server_banner(resp)
    findings += check_cookie_flags(resp)
    findings += check_outdated_libraries(resp)
    return findings
