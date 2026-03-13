"""
fetcher.py
----------
Fetches CVE details from the NVD (National Vulnerability Database) public API.
No API key required for basic usage.

NVD API Docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import requests

# Base URL for the NVD CVE API
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve(cve_id: str) -> dict:
    """
    Fetch details for a given CVE ID from the NVD API.

    Args:
        cve_id (str): The CVE ID, e.g. 'CVE-2021-44228'

    Returns:
        dict: Parsed CVE data with the following keys:
            - id: CVE ID
            - description: What the vulnerability is
            - severity: LOW / MEDIUM / HIGH / CRITICAL
            - score: CVSS score (0.0 - 10.0)
            - published: Date it was published
            - references: List of useful URLs

    Raises:
        ValueError: If CVE is not found or ID is invalid
        ConnectionError: If the API is unreachable
    """

    # Basic format check before hitting the API
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        raise ValueError(f"Invalid CVE format: '{cve_id}'. Expected format: CVE-YYYY-NNNNN")

    params = {"cveId": cve_id}

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=10)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise ConnectionError("Could not reach NVD API. Check your internet connection.")
    except requests.exceptions.Timeout:
        raise ConnectionError("NVD API timed out. Try again in a moment.")
    except requests.exceptions.HTTPError as e:
        raise ValueError(f"API error: {e}")

    data = response.json()

    # Check if any results were returned
    total = data.get("totalResults", 0)
    if total == 0:
        raise ValueError(f"CVE '{cve_id}' not found in NVD database.")

    # Drill into the nested JSON structure NVD returns
    raw = data["vulnerabilities"][0]["cve"]

    # --- Extract description ---
    description = "No description available."
    for desc in raw.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc["value"]
            break

    # --- Extract severity + CVSS score ---
    severity = "UNKNOWN"
    score = "N/A"

    metrics = raw.get("metrics", {})

    # Try CVSS v3.1 first, then v3.0, then v2.0
    if "cvssMetricV31" in metrics:
        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
        severity = cvss_data.get("baseSeverity", "UNKNOWN")
        score = cvss_data.get("baseScore", "N/A")
    elif "cvssMetricV30" in metrics:
        cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
        severity = cvss_data.get("baseSeverity", "UNKNOWN")
        score = cvss_data.get("baseScore", "N/A")
    elif "cvssMetricV2" in metrics:
        cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
        score = cvss_data.get("baseScore", "N/A")

    # --- Extract published date ---
    published = raw.get("published", "Unknown date")
    if "T" in published:
        published = published.split("T")[0]  # Just keep YYYY-MM-DD

    # --- Extract reference URLs ---
    references = []
    for ref in raw.get("references", [])[:5]:  # Limit to 5 refs
        url = ref.get("url", "")
        if url:
            references.append(url)

    return {
        "id": cve_id,
        "description": description,
        "severity": severity,
        "score": score,
        "published": published,
        "references": references,
    }


def print_cve_summary(cve: dict) -> None:
    """
    Pretty-prints a CVE summary to the terminal.

    Args:
        cve (dict): CVE data returned by fetch_cve()
    """

    # Color codes for severity
    severity_colors = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH":     "\033[91m",  # Red
        "MEDIUM":   "\033[93m",  # Yellow
        "LOW":      "\033[92m",  # Green
        "UNKNOWN":  "\033[90m",  # Grey
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    CYAN  = "\033[96m"

    color = severity_colors.get(cve["severity"], "\033[90m")

    print(f"\n{BOLD}{CYAN}{'='*50}{RESET}")
    print(f"{BOLD}  {cve['id']}{RESET}")
    print(f"{CYAN}{'='*50}{RESET}")
    print(f"  {BOLD}Published :{RESET} {cve['published']}")
    print(f"  {BOLD}Severity  :{RESET} {color}{cve['severity']} (Score: {cve['score']} / 10){RESET}")
    print(f"\n  {BOLD}Description:{RESET}")

    # Word-wrap description at 65 chars for readability
    words = cve["description"].split()
    line = "    "
    for word in words:
        if len(line) + len(word) + 1 > 70:
            print(line)
            line = "    " + word + " "
        else:
            line += word + " "
    if line.strip():
        print(line)

    if cve["references"]:
        print(f"\n  {BOLD}References:{RESET}")
        for ref in cve["references"]:
            print(f"    - {ref}")

    print(f"{CYAN}{'='*50}{RESET}\n")


# ── Quick test ──────────────────────────────────────────
# Run this file directly to test: python fetcher.py
if __name__ == "__main__":
    test_cve = "CVE-2021-44228"  # Log4Shell - famous one to test with
    print(f"Fetching {test_cve}...")

    try:
        cve = fetch_cve(test_cve)
        print_cve_summary(cve)
    except (ValueError, ConnectionError) as e:
        print(f"Error: {e}")