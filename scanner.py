#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WordPress Security Checker

A simple tool for reviewing WordPress websites and finding basic
security and configuration issues.

Use only on websites you own or have permission to test.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


USER_AGENT = "WordPress-Security-Checker/1.0"
TIMEOUT = 12


@dataclass
class Finding:
    severity: str
    title: str
    details: str
    location: str
    recommendation: str


def normalize_url(url: str) -> str:
    url = url.strip()

    if not url:
        return ""

    if not re.match(r"^https?://", url, flags=re.I):
        url = "https://" + url

    return url


def fetch(
    session: requests.Session,
    url: str,
    method: str = "GET"
) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        if method.upper() == "HEAD":
            response = session.head(url, allow_redirects=True, timeout=TIMEOUT)
        else:
            response = session.get(url, allow_redirects=True, timeout=TIMEOUT)

        return response, None

    except requests.RequestException as error:
        return None, str(error)


def add_finding(
    results: List[Finding],
    severity: str,
    title: str,
    details: str,
    location: str,
    recommendation: str
) -> None:
    results.append(
        Finding(
            severity=severity,
            title=title,
            details=details,
            location=location,
            recommendation=recommendation
        )
    )


def is_wordpress(response: requests.Response) -> bool:
    body = response.text.lower()

    indicators = [
        "/wp-content/",
        "/wp-includes/",
        "wp-json"
    ]

    if any(item in body for item in indicators):
        return True

    pingback = response.headers.get("X-Pingback", "")
    return "xmlrpc.php" in pingback.lower()


def check_headers(response: requests.Response, results: List[Finding]) -> None:
    headers = {key.lower(): value for key, value in response.headers.items()}
    final_url = response.url

    if not final_url.startswith("https://"):
        add_finding(
            results,
            "critical",
            "HTTPS is not enforced",
            "The final resolved URL does not use HTTPS.",
            final_url,
            "Redirect all HTTP traffic to HTTPS."
        )

    if "strict-transport-security" not in headers:
        add_finding(
            results,
            "medium",
            "Missing HSTS header",
            "Strict-Transport-Security header was not found.",
            final_url,
            "Add HSTS after HTTPS is configured correctly."
        )

    content_type = headers.get("x-content-type-options", "")
    if content_type.lower() != "nosniff":
        add_finding(
            results,
            "medium",
            "Missing or weak X-Content-Type-Options",
            f"Current value: {content_type or 'missing'}",
            final_url,
            "Set X-Content-Type-Options to nosniff."
        )

    has_frame_options = "x-frame-options" in headers
    csp = headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if not has_frame_options and not has_frame_ancestors:
        add_finding(
            results,
            "medium",
            "Missing clickjacking protection",
            "No X-Frame-Options or CSP frame-ancestors directive was detected.",
            final_url,
            "Use X-Frame-Options or CSP frame-ancestors."
        )

    if "content-security-policy" not in headers:
        add_finding(
            results,
            "low",
            "Missing Content-Security-Policy",
            "No CSP header was detected.",
            final_url,
            "Consider adding a CSP after testing scripts and styles."
        )

    if "referrer-policy" not in headers:
        add_finding(
            results,
            "low",
            "Missing Referrer-Policy",
            "No Referrer-Policy header was detected.",
            final_url,
            "Set a Referrer-Policy such as strict-origin-when-cross-origin."
        )


def check_generator_meta(response: requests.Response, results: List[Finding]) -> None:
    match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        response.text,
        flags=re.I,
    )

    if not match:
        return

    content = match.group(1)

    if "wordpress" in content.lower():
        add_finding(
            results,
            "low",
            "WordPress version disclosure",
            f"Generator meta tag exposed: {content}",
            response.url,
            "Remove the generator meta tag if it is not needed."
        )


def check_readme(session: requests.Session, base_url: str, results: List[Finding]) -> None:
    url = urljoin(base_url.rstrip("/") + "/", "readme.html")
    response, _ = fetch(session, url)

    if response is not None and response.status_code == 200:
        add_finding(
            results,
            "low",
            "Public readme.html exposed",
            "The WordPress readme file is publicly accessible.",
            url,
            "Remove or block access to readme.html."
        )


def check_xmlrpc(session: requests.Session, base_url: str, results: List[Finding]) -> None:
    url = urljoin(base_url.rstrip("/") + "/", "xmlrpc.php")
    response, _ = fetch(session, url)

    if response is not None and response.status_code in (200, 405):
        add_finding(
            results,
            "medium",
            "xmlrpc.php appears accessible",
            f"Status code: {response.status_code}",
            url,
            "Disable or restrict xmlrpc.php if it is not required."
        )


def check_rest_api(session: requests.Session, base_url: str, results: List[Finding]) -> None:
    url = urljoin(base_url.rstrip("/") + "/", "wp-json/")
    response, _ = fetch(session, url)

    if response is not None and response.status_code == 200:
        add_finding(
            results,
            "info",
            "REST API is publicly reachable",
            "The WordPress REST API endpoint responded successfully.",
            url,
            "Review public REST endpoints and exposed data."
        )


def check_user_enumeration(
    session: requests.Session,
    base_url: str,
    results: List[Finding]
) -> None:
    url = base_url.rstrip("/") + "/?author=1"
    response, _ = fetch(session, url)

    if response is None:
        return

    parsed_url = urlparse(response.url)

    if "/author/" in parsed_url.path.lower():
        add_finding(
            results,
            "medium",
            "Possible user enumeration",
            f"Redirected to author archive path: {parsed_url.path}",
            url,
            "Disable author enumeration or hide author archive slugs."
        )


def check_directory_listing(
    session: requests.Session,
    base_url: str,
    results: List[Finding]
) -> None:
    paths = [
        "wp-content/uploads/",
        "wp-content/plugins/",
        "wp-content/themes/",
    ]

    patterns = [
        "index of /",
        "directory listing for",
        "parent directory",
    ]

    for path in paths:
        url = urljoin(base_url.rstrip("/") + "/", path)
        response, _ = fetch(session, url)

        if response is None or response.status_code != 200:
            continue

        body = response.text.lower()

        if any(pattern in body for pattern in patterns):
            add_finding(
                results,
                "medium",
                "Possible directory listing enabled",
                f"Directory listing indicators found for {path}",
                url,
                "Disable directory listing on the server."
            )


def extract_assets_and_plugins(response: requests.Response) -> Tuple[List[str], List[str]]:
    soup = BeautifulSoup(response.text, "html.parser")

    asset_urls: List[str] = []
    plugins: List[str] = []

    for tag in soup.find_all(["script", "link", "img"]):
        attribute = "src" if tag.name in ("script", "img") else "href"
        value = tag.get(attribute)

        if not value:
            continue

        asset_urls.append(value)

        match = re.search(r"/wp-content/plugins/([^/]+)/", value)
        if match:
            plugins.append(match.group(1))

    return asset_urls, sorted(set(plugins))


def check_exposed_versions(response: requests.Response, results: List[Finding]) -> None:
    assets, plugins = extract_assets_and_plugins(response)

    for asset in assets:
        if "/wp-content/plugins/" not in asset and "/wp-content/themes/" not in asset:
            continue

        match = re.search(r"[?&](?:ver|version)=([0-9][^&#]*)", asset, flags=re.I)

        if match:
            add_finding(
                results,
                "info",
                "Asset version parameter exposed",
                f"Version value found in asset URL: {match.group(1)}",
                asset,
                "Version hiding is not a full defense, but it can reduce information exposure."
            )

    if plugins:
        add_finding(
            results,
            "info",
            "Detected WordPress plugins",
            ", ".join(plugins),
            response.url,
            "Review detected plugins and keep them updated."
        )


def check_login_page(session: requests.Session, base_url: str, results: List[Finding]) -> None:
    url = urljoin(base_url.rstrip("/") + "/", "wp-login.php")
    response, _ = fetch(session, url)

    if response is None or response.status_code != 200:
        return

    body = response.text.lower()

    if "log in" in body or "login" in body or "user_login" in body:
        add_finding(
            results,
            "info",
            "Login page exposed at default location",
            "The default WordPress login page appears reachable.",
            url,
            "Use strong passwords, 2FA, rate limiting, and bot protection."
        )


def check_forms(response: requests.Response, results: List[Finding]) -> None:
    # Basic frontend form review.
    # This is only a simple indicator and should be checked manually.
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")

    for index, form in enumerate(forms, start=1):
        hidden_inputs = form.find_all("input", {"type": "hidden"})
        hidden_names = [
            str(input_field.get("name", "")).lower()
            for input_field in hidden_inputs
        ]

        has_token = any(
            "csrf" in name or "token" in name or "nonce" in name
            for name in hidden_names
        )

        action = form.get("action") or response.url

        if not has_token:
            add_finding(
                results,
                "info",
                "Form should be reviewed",
                f"No obvious token or nonce field detected in form #{index}.",
                action,
                "Review this form manually and confirm CSRF protection."
            )


def print_results(results: List[Finding]) -> None:
    if not results:
        print("\nNo obvious issues found by these basic checks.")
        print("This does not guarantee the website is fully secure.\n")
        return

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4
    }

    sorted_results = sorted(
        results,
        key=lambda item: severity_order.get(item.severity, 99)
    )

    print("\nFindings:\n")

    for index, finding in enumerate(sorted_results, start=1):
        print(f"[{index}] {finding.severity.upper()} - {finding.title}")
        print(f"    Details        : {finding.details}")
        print(f"    Found at       : {finding.location}")
        print(f"    Recommendation : {finding.recommendation}")
        print()


def run_scan(url: str, skip_form_check: bool = False) -> int:
    normalized_url = normalize_url(url)

    if not normalized_url:
        print("Please provide a valid URL.")
        return 1

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    response, error = fetch(session, normalized_url)

    if response is None:
        print(f"Failed to fetch target: {error}")
        return 1

    print(f"\nTarget    : {normalized_url}")
    print(f"Resolved  : {response.url}")
    print(f"HTTP code : {response.status_code}")

    if not is_wordpress(response):
        print("\nThe homepage does not clearly look like a WordPress site.")
        print("The scanner will still run basic checks.\n")

    results: List[Finding] = []

    check_headers(response, results)
    check_generator_meta(response, results)
    check_exposed_versions(response, results)
    check_readme(session, response.url, results)
    check_xmlrpc(session, response.url, results)
    check_rest_api(session, response.url, results)
    check_user_enumeration(session, response.url, results)
    check_directory_listing(session, response.url, results)
    check_login_page(session, response.url, results)

    if not skip_form_check:
        check_forms(response, results)

    print_results(results)

    print("Note:")
    print("- This is a basic security review, not a full penetration test.")
    print("- The scanner does not exploit or attack the website.")
    print("- Keep WordPress core, themes, and plugins updated.")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Basic WordPress security checker."
    )

    parser.add_argument(
        "url",
        help="Target URL, for example: https://example.com"
    )

    parser.add_argument(
        "--skip-form-check",
        action="store_true",
        help="Skip the basic frontend form review"
    )

    args = parser.parse_args()

    return run_scan(
        url=args.url,
        skip_form_check=args.skip_form_check
    )


if __name__ == "__main__":
    sys.exit(main())
