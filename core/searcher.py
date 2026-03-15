"""
core/searcher.py
----------------
Searches the NVD API by keyword instead of exact CVE ID.
Lets you type 'log4j' or 'windows smb rce' and get matching CVEs.

NVD keyword search docs:
https://nvd.nist.gov/developers/vulnerabilities

Usage (standalone):
    python core/searcher.py log4j
    python core/searcher.py "windows smb rce"

Usage (from cli.py):
    from core.searcher import search_cves
    results = search_cves("log4j")
"""

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cves(keyword: str, limit: int = 10) -> list:
    """
    Searches NVD for CVEs matching a keyword.

    Args:
        keyword (str): Search term e.g. 'log4j', 'windows smb rce'
        limit (int):   Max results to return (default 10)

    Returns:
        list of dicts with keys:
            - id, description, severity, score, published

    Raises:
        ConnectionError: If NVD API is unreachable
        ValueError: If no results found
    """

    params = {
        "keywordSearch": keyword.strip(),
        "resultsPerPage": limit,
        "startIndex": 0,
    }

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=10)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise ConnectionError("Could not reach NVD API. Check your internet connection.")
    except requests.exceptions.Timeout:
        raise ConnectionError("NVD API timed out. Try again in a moment.")
    except requests.exceptions.HTTPError as e:
        raise ValueError(f"API error: {e}")

    data  = response.json()
    total = data.get("totalResults", 0)

    if total == 0:
        raise ValueError(f"No CVEs found matching '{keyword}'.")

    results = []

    for item in data.get("vulnerabilities", []):
        raw = item.get("cve", {})

        # Description
        description = "No description available."
        for desc in raw.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc["value"]
                break

        # Severity + score
        severity = "UNKNOWN"
        score    = "N/A"
        metrics  = raw.get("metrics", {})

        if "cvssMetricV31" in metrics:
            cvss     = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "UNKNOWN")
            score    = cvss.get("baseScore", "N/A")
        elif "cvssMetricV30" in metrics:
            cvss     = metrics["cvssMetricV30"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "UNKNOWN")
            score    = cvss.get("baseScore", "N/A")
        elif "cvssMetricV2" in metrics:
            cvss     = metrics["cvssMetricV2"][0]["cvssData"]
            severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
            score    = cvss.get("baseScore", "N/A")

        # Published date
        published = raw.get("published", "Unknown")
        if "T" in published:
            published = published.split("T")[0]

        results.append({
            "id":          raw.get("id", ""),
            "description": description,
            "severity":    severity,
            "score":       score,
            "published":   published,
        })

    return results


# ── Quick test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    keyword = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "log4j"
    print(f"Searching NVD for: '{keyword}'\n")

    try:
        results = search_cves(keyword)
        for r in results:
            print(f"  {r['id']}  [{r['severity']} {r['score']}]  {r['published']}")
            print(f"  {r['description'][:80]}...")
            print()
    except (ValueError, ConnectionError) as e:
        print(f"Error: {e}")