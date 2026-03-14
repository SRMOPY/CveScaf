"""
resources.py
------------
Matches a CVE to learning platforms and free resources:
  - TryHackMe rooms
  - HackTheBox machines
  - VulnHub VMs (free)
  - ExploitDB entries
  - YouTube walkthroughs

Usage (standalone):
    python resources.py CVE-2021-44228

Usage (from cli.py):
    from resources import get_resources
    results = get_resources("CVE-2021-44228")
"""

import requests

# ── Resource database ─────────────────────────────────────────────────────────
# Manually curated and verified.
# Format per entry:
#   "CVE-ID": {
#       "thm":      [{ name, url, free, difficulty }]
#       "htb":      [{ name, url, free, difficulty }]
#       "vulnhub":  [{ name, url }]              <- always free
#       "exploitdb":[{ id, title, url }]
#       "youtube":  [{ title, url }]
#   }

RESOURCE_MAP = {
    "CVE-2021-44228": {
        "thm": [
            {
                "name":       "Solar, exploiting log4j",
                "url":        "https://tryhackme.com/room/solar",
                "free":       False,
                "difficulty": "Medium",
            },
            {
                "name":       "Log4j CVE-2021-44228",
                "url":        "https://tryhackme.com/room/cvelog4j",
                "free":       False,
                "difficulty": "Easy",
            },
        ],
        "htb": [],
        "vulnhub": [],
        "exploitdb": [
            {
                "id":    "51183",
                "title": "Apache Log4j 2.14.1 - Remote Code Execution",
                "url":   "https://www.exploit-db.com/exploits/51183",
            },
        ],
        "youtube": [
            {
                "title": "Log4Shell Full Walkthrough - John Hammond",
                "url":   "https://www.youtube.com/watch?v=7qoppjMFyv8",
            },
        ],
    },

    "CVE-2017-0144": {
        "thm": [
            {
                "name":       "Blue",
                "url":        "https://tryhackme.com/room/blue",
                "free":       True,
                "difficulty": "Easy",
            },
        ],
        "htb": [
            {
                "name":       "Blue",
                "url":        "https://app.hackthebox.com/machines/Blue",
                "free":       False,
                "difficulty": "Easy",
            },
        ],
        "vulnhub": [],
        "exploitdb": [
            {
                "id":    "42315",
                "title": "MS17-010 EternalBlue SMB Remote Code Execution",
                "url":   "https://www.exploit-db.com/exploits/42315",
            },
        ],
        "youtube": [
            {
                "title": "EternalBlue / MS17-010 Exploitation Tutorial",
                "url":   "https://www.youtube.com/watch?v=6PzLMTesMpc",
            },
        ],
    },

    "CVE-2019-0708": {
        "thm": [],
        "htb": [],
        "vulnhub": [],
        "exploitdb": [
            {
                "id":    "47416",
                "title": "BlueKeep RDP Remote Windows Kernel Use After Free",
                "url":   "https://www.exploit-db.com/exploits/47416",
            },
        ],
        "youtube": [
            {
                "title": "BlueKeep CVE-2019-0708 Metasploit Demo",
                "url":   "https://www.youtube.com/watch?v=Bns5LcI5vls",
            },
        ],
    },

    "CVE-2014-6271": {
        "thm": [
            {
                "name":       "Shellshock",
                "url":        "https://tryhackme.com/room/shellshockctf",
                "free":       False,
                "difficulty": "Easy",
            },
        ],
        "htb": [],
        "vulnhub": [
            {
                "name": "Kioptrix Level 2014",
                "url":  "https://www.vulnhub.com/entry/kioptrix-2014-5,62/",
            },
        ],
        "exploitdb": [
            {
                "id":    "34765",
                "title": "GNU Bash - Environment Variable Command Injection (Shellshock)",
                "url":   "https://www.exploit-db.com/exploits/34765",
            },
        ],
        "youtube": [
            {
                "title": "Shellshock Attack Explained",
                "url":   "https://www.youtube.com/watch?v=aKShnpOXqn0",
            },
        ],
    },

    "CVE-2021-3156": {
        "thm": [
            {
                "name":       "Baron Samedit",
                "url":        "https://tryhackme.com/room/sudovulnsbypass",
                "free":       False,
                "difficulty": "Medium",
            },
        ],
        "htb": [],
        "vulnhub": [],
        "exploitdb": [
            {
                "id":    "49521",
                "title": "sudo 1.8.31p2 - Heap-Based Buffer Overflow",
                "url":   "https://www.exploit-db.com/exploits/49521",
            },
        ],
        "youtube": [
            {
                "title": "CVE-2021-3156 Baron Samedit Sudo LPE Demo",
                "url":   "https://www.youtube.com/watch?v=TLa2VqcGGEQ",
            },
        ],
    },

    "CVE-2020-1472": {
        "thm": [
            {
                "name":       "Zero Logon",
                "url":        "https://tryhackme.com/room/zer0logon",
                "free":       False,
                "difficulty": "Hard",
            },
        ],
        "htb": [],
        "vulnhub": [],
        "exploitdb": [
            {
                "id":    "49071",
                "title": "Microsoft Zerologon - Privilege Escalation",
                "url":   "https://www.exploit-db.com/exploits/49071",
            },
        ],
        "youtube": [
            {
                "title": "Zerologon Attack Full Walkthrough",
                "url":   "https://www.youtube.com/watch?v=FZB6bKQyM-0",
            },
        ],
    },

    "CVE-2017-7494": {
        "thm": [],
        "htb": [],
        "vulnhub": [
            {
                "name": "SickOs 1.2",
                "url":  "https://www.vulnhub.com/entry/sickos-12,144/",
            },
        ],
        "exploitdb": [
            {
                "id":    "42060",
                "title": "Samba 3.5.0 - Remote Code Execution (SambaCry)",
                "url":   "https://www.exploit-db.com/exploits/42060",
            },
        ],
        "youtube": [
            {
                "title": "SambaCry CVE-2017-7494 Exploitation Demo",
                "url":   "https://www.youtube.com/watch?v=oU4CQFLLvmc",
            },
        ],
    },
}


# ── Main function ─────────────────────────────────────────────────────────────

def get_resources(cve_id: str) -> dict:
    """
    Returns all known learning resources for a CVE.

    Args:
        cve_id (str): e.g. 'CVE-2021-44228'

    Returns:
        dict with keys: cve_id, thm, htb, vulnhub, exploitdb, youtube, found
        'found' is True if we have curated resources, False if unknown CVE
    """
    cve_id  = cve_id.strip().upper()
    data    = RESOURCE_MAP.get(cve_id)

    if not data:
        return {
            "cve_id":    cve_id,
            "thm":       [],
            "htb":       [],
            "vulnhub":   [],
            "exploitdb": [],
            "youtube":   [],
            "found":     False,
        }

    return {
        "cve_id":    cve_id,
        "thm":       data.get("thm",       []),
        "htb":       data.get("htb",       []),
        "vulnhub":   data.get("vulnhub",   []),
        "exploitdb": data.get("exploitdb", []),
        "youtube":   data.get("youtube",   []),
        "found":     True,
    }


def print_resources(results: dict) -> None:
    """
    Pretty-prints resources to terminal.
    Used when running resources.py standalone.
    """
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    cve_id = results["cve_id"]

    print("\n" + BOLD + CYAN + "=" * 55 + RESET)
    print(BOLD + "  Learning Resources for " + cve_id + RESET)
    print(CYAN + "=" * 55 + RESET + "\n")

    if not results["found"]:
        print(YELLOW + "  [!] No curated resources found for " + cve_id + "." + RESET)
        print(DIM + "  Try searching manually:" + RESET)
        print(DIM + "    https://tryhackme.com/hacktivities?q=" + cve_id + RESET)
        print(DIM + "    https://www.exploit-db.com/search?cve=" + cve_id[4:] + RESET)
        print(DIM + "    https://github.com/search?q=" + cve_id + "&type=repositories" + RESET)
        print()
        return

    # TryHackMe
    print(BOLD + "  [THM] TryHackMe Rooms:" + RESET)
    if results["thm"]:
        for room in results["thm"]:
            free_tag = GREEN + "[FREE]" + RESET if room["free"] else YELLOW + "[Subscription]" + RESET
            print("    " + free_tag + " " + BOLD + room["name"] + RESET + " (" + room["difficulty"] + ")")
            print("    " + CYAN + room["url"] + RESET)
    else:
        print("    " + DIM + "No THM rooms found for this CVE." + RESET)

    # HackTheBox
    print("\n" + BOLD + "  [HTB] HackTheBox Machines:" + RESET)
    if results["htb"]:
        for machine in results["htb"]:
            free_tag = GREEN + "[FREE]" + RESET if machine["free"] else YELLOW + "[VIP]" + RESET
            print("    " + free_tag + " " + BOLD + machine["name"] + RESET + " (" + machine["difficulty"] + ")")
            print("    " + CYAN + machine["url"] + RESET)
    else:
        print("    " + DIM + "No HTB machines found for this CVE." + RESET)

    # VulnHub (always free)
    print("\n" + BOLD + "  [VHL] VulnHub (Free):" + RESET)
    if results["vulnhub"]:
        for vm in results["vulnhub"]:
            print("    " + GREEN + "[FREE]" + RESET + " " + BOLD + vm["name"] + RESET)
            print("    " + CYAN + vm["url"] + RESET)
    else:
        print("    " + DIM + "No VulnHub VMs found for this CVE." + RESET)

    # ExploitDB
    print("\n" + BOLD + "  [EDB] ExploitDB:" + RESET)
    if results["exploitdb"]:
        for edb in results["exploitdb"]:
            print("    " + GREEN + "EDB-" + edb["id"] + RESET + " - " + edb["title"])
            print("    " + CYAN + edb["url"] + RESET)
    else:
        print("    " + DIM + "No ExploitDB entries found for this CVE." + RESET)

    # YouTube
    print("\n" + BOLD + "  [YT] YouTube Walkthroughs:" + RESET)
    if results["youtube"]:
        for yt in results["youtube"]:
            print("    " + RED + yt["title"] + RESET)
            print("    " + CYAN + yt["url"] + RESET)
    else:
        print("    " + DIM + "No YouTube walkthroughs found." + RESET)

    print("\n" + CYAN + "=" * 55 + RESET + "\n")


# ── Quick test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    cve = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    results = get_resources(cve)
    print_resources(results)