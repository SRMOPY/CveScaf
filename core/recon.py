"""
recon.py
--------
Automatically finds exploitation resources for a given CVE:
  - PoC exploits on GitHub
  - Matching Metasploit modules
  - Writeups and blog posts via Google dorking (requests)

No API key needed for basic usage.
Optional: set GITHUB_TOKEN in a .env file for higher rate limits.

Usage (standalone):
    python recon.py CVE-2021-44228

Usage (from cli.py):
    from recon import run_recon
    results = run_recon("CVE-2021-44228")
"""

import os
import requests

# ── Optional GitHub token from environment ────────────────────────────────────
# To use: create a .env file in the project folder with:
#   GITHUB_TOKEN=your_token_here
# Then pip install python-dotenv and uncomment the lines below.
#
# from dotenv import load_dotenv
# load_dotenv()

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", None)

GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
}
if GITHUB_TOKEN:
    GITHUB_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"


# ── Known Metasploit modules for popular CVEs ─────────────────────────────────
# We maintain this manually for reliability.
# Format: "CVE-ID": ["module/path", ...]

METASPLOIT_MAP = {
    "CVE-2021-44228": [
        "exploit/multi/http/log4shell_header_injection",
    ],
    "CVE-2017-0144": [
        "exploit/windows/smb/ms17_010_eternalblue",
        "exploit/windows/smb/ms17_010_psexec",
    ],
    "CVE-2017-7494": [
        "exploit/linux/samba/is_known_pipename",
    ],
    "CVE-2019-0708": [
        "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
    ],
    "CVE-2014-6271": [
        "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    ],
    "CVE-2021-3156": [
        "exploit/linux/local/sudo_baron_samedit",
    ],
    "CVE-2020-1472": [
        "exploit/windows/dcerpc/cve_2020_1472_zerologon",
    ],
    "CVE-2019-11043": [
        "exploit/multi/http/php_fpm_rce",
    ],
}


# ── GitHub PoC search ─────────────────────────────────────────────────────────

def search_github_pocs(cve_id: str, limit: int = 5) -> list:
    """
    Searches GitHub for PoC repositories matching the CVE ID.

    Args:
        cve_id (str): e.g. 'CVE-2021-44228'
        limit (int): Max results to return

    Returns:
        list of dicts with keys: name, url, description, stars
    """

    url    = "https://api.github.com/search/repositories"
    params = {
        "q":        f"{cve_id} poc exploit",
        "sort":     "stars",
        "order":    "desc",
        "per_page": limit,
    }

    try:
        response = requests.get(url, headers=GITHUB_HEADERS, params=params, timeout=10)

        # Check rate limit
        if response.status_code == 403:
            return [{"error": "GitHub rate limit hit. Wait 60 seconds or add a GITHUB_TOKEN."}]
        if response.status_code == 422:
            return []

        response.raise_for_status()
        data  = response.json()
        items = data.get("items", [])

        results = []
        for item in items:
            results.append({
                "name":        item.get("full_name", ""),
                "url":         item.get("html_url", ""),
                "description": item.get("description") or "No description",
                "stars":       item.get("stargazers_count", 0),
            })
        return results

    except requests.exceptions.ConnectionError:
        return [{"error": "No internet connection."}]
    except requests.exceptions.Timeout:
        return [{"error": "GitHub API timed out."}]
    except Exception as e:
        return [{"error": str(e)}]


def search_github_code(cve_id: str, limit: int = 3) -> list:
    """
    Searches GitHub CODE (not just repos) for scripts mentioning the CVE.
    Good for finding standalone exploit scripts.

    Args:
        cve_id (str): e.g. 'CVE-2021-44228'
        limit (int): Max results to return

    Returns:
        list of dicts with keys: name, url, repo
    """

    url    = "https://api.github.com/search/code"
    params = {
        "q":        f"{cve_id} exploit",
        "per_page": limit,
    }

    try:
        response = requests.get(url, headers=GITHUB_HEADERS, params=params, timeout=10)

        if response.status_code in (403, 422):
            return []

        response.raise_for_status()
        data  = response.json()
        items = data.get("items", [])

        results = []
        for item in items:
            results.append({
                "name": item.get("name", ""),
                "url":  item.get("html_url", ""),
                "repo": item.get("repository", {}).get("full_name", ""),
            })
        return results

    except Exception:
        return []


# ── Metasploit lookup ─────────────────────────────────────────────────────────

def get_metasploit_modules(cve_id: str) -> list:
    """
    Returns known Metasploit modules for a CVE.

    Args:
        cve_id (str): e.g. 'CVE-2021-44228'

    Returns:
        list of module path strings, empty list if none known
    """
    return METASPLOIT_MAP.get(cve_id.upper(), [])


# ── Writeup search ────────────────────────────────────────────────────────────

def search_writeups(cve_id: str, limit: int = 5) -> list:
    """
    Searches GitHub for writeups, blogs, and analysis of the CVE.

    Args:
        cve_id (str): e.g. 'CVE-2021-44228'
        limit (int): Max results to return

    Returns:
        list of dicts with keys: name, url, description, stars
    """

    url    = "https://api.github.com/search/repositories"
    params = {
        "q":        f"{cve_id} writeup analysis",
        "sort":     "stars",
        "order":    "desc",
        "per_page": limit,
    }

    try:
        response = requests.get(url, headers=GITHUB_HEADERS, params=params, timeout=10)

        if response.status_code in (403, 422):
            return []

        response.raise_for_status()
        data  = response.json()
        items = data.get("items", [])

        results = []
        for item in items:
            results.append({
                "name":        item.get("full_name", ""),
                "url":         item.get("html_url", ""),
                "description": item.get("description") or "No description",
                "stars":       item.get("stargazers_count", 0),
            })
        return results

    except Exception:
        return []


# ── Main recon runner ─────────────────────────────────────────────────────────

def run_recon(cve_id: str) -> dict:
    """
    Runs all recon functions for a CVE and returns combined results.

    Args:
        cve_id (str): e.g. 'CVE-2021-44228'

    Returns:
        dict with keys: cve_id, pocs, metasploit, writeups, code_results
    """

    cve_id = cve_id.strip().upper()

    pocs       = search_github_pocs(cve_id)
    msf        = get_metasploit_modules(cve_id)
    writeups   = search_writeups(cve_id)
    code       = search_github_code(cve_id)

    return {
        "cve_id":       cve_id,
        "pocs":         pocs,
        "metasploit":   msf,
        "writeups":     writeups,
        "code_results": code,
    }


def print_recon(results: dict) -> None:
    """
    Pretty-prints recon results to the terminal.
    Used when running recon.py standalone.

    Args:
        results (dict): Output from run_recon()
    """

    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    cve_id = results["cve_id"]

    print(f"\n{BOLD}{CYAN}{'='*55}{RESET}")
    print(f"{BOLD}  Recon Results for {cve_id}{RESET}")
    print(f"{CYAN}{'='*55}{RESET}\n")

    # ── Metasploit ────────────────────────────────────────────────────────────
    print(f"{BOLD}  [MSF] Metasploit Modules:{RESET}")
    if results["metasploit"]:
        for mod in results["metasploit"]:
            print(f"    {GREEN}use {mod}{RESET}")
    else:
        print(f"    {DIM}No known Metasploit module for this CVE.{RESET}")

    # ── PoCs ──────────────────────────────────────────────────────────────────
    print(f"\n{BOLD}  [POC] GitHub PoC Repositories:{RESET}")
    if results["pocs"]:
        for poc in results["pocs"]:
            if "error" in poc:
                print(f"    {YELLOW}[!] {poc['error']}{RESET}")
            else:
                stars = poc['stars']
                print(f"    {GREEN}{poc['name']}{RESET} ({stars} stars)")
                print(f"    {DIM}  {poc['description']}{RESET}")
                print(f"    {CYAN}  {poc['url']}{RESET}\n")
    else:
        print(f"    {DIM}No PoC repositories found.{RESET}")

    # ── Writeups ──────────────────────────────────────────────────────────────
    print(f"\n{BOLD}  [WRT] Writeups & Analysis:{RESET}")
    if results["writeups"]:
        for w in results["writeups"]:
            print(f"    {GREEN}{w['name']}{RESET}")
            print(f"    {DIM}  {w['description']}{RESET}")
            print(f"    {CYAN}  {w['url']}{RESET}\n")
    else:
        print(f"    {DIM}No writeups found.{RESET}")

    # ── Code results ──────────────────────────────────────────────────────────
    if results["code_results"]:
        print(f"\n{BOLD}  [CODE] Exploit Scripts Found:{RESET}")
        for c in results["code_results"]:
            print(f"    {GREEN}{c['name']}{RESET} in {c['repo']}")
            print(f"    {CYAN}  {c['url']}{RESET}\n")

    print(f"{CYAN}{'='*55}{RESET}\n")


# ── Quick test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    cve = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    print(f"Running recon for {cve}...")
    results = run_recon(cve)
    print_recon(results)