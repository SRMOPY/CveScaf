"""
cli.py
------
Main entry point for CVE Scaffolder.

Usage:
    python cli.py lookup CVE-2021-44228
    python cli.py recon CVE-2021-44228
    python cli.py resources CVE-2021-44228
    python cli.py note-gen CVE-2021-44228
    python cli.py list-cves
    python cli.py history
    python cli.py note CVE-2021-44228 "my note here"
    python cli.py --help

Requirements:
    pip install typer rich requests
"""

import typer
import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

from fetcher import fetch_cve
from db import init_db, save_cve, get_history, get_stats, add_note
from recon import run_recon
from resources import get_resources
from notes import generate_note

# Initialize database on startup
init_db()

# ── App setup ─────────────────────────────────────────────────────────────────

app = typer.Typer(
    name           = "cvescaf",
    help           = "CveScaf — Look up CVEs, find exploits, and build your attack lab.",
    add_completion = False,
)
console = Console()

# ── Severity color map ────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "UNKNOWN":  "dim",
}

# ── Known CVEs for list-cves ──────────────────────────────────────────────────

KNOWN_CVES = [
    ("CVE-2021-44228", "Log4Shell",     "Apache Log4j2",    "CRITICAL", "10.0"),
    ("CVE-2017-7494",  "SambaCry",      "Samba",            "CRITICAL", "9.8"),
    ("CVE-2014-6271",  "Shellshock",    "Bash",             "CRITICAL", "9.8"),
    ("CVE-2021-3156",  "Baron Samedit", "sudo",             "HIGH",     "7.8"),
    ("CVE-2019-11043", "PHP-FPM RCE",   "PHP-FPM/Nginx",    "CRITICAL", "9.8"),
    ("CVE-2019-0708",  "BlueKeep",      "Windows RDP",      "CRITICAL", "9.8"),
    ("CVE-2017-0144",  "EternalBlue",   "Windows SMB",      "HIGH",     "8.8"),
    ("CVE-2020-1472",  "Zerologon",     "Windows Netlogon", "CRITICAL", "10.0"),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def truncate(text, length=60):
    return (text[:length] + "...") if len(text) > length else text


# ── Commands ──────────────────────────────────────────────────────────────────

@app.command()
def lookup(
    cve_id: str  = typer.Argument(..., help="CVE ID to look up. Example: CVE-2021-44228"),
    hints:  bool = typer.Option(False, "--hints", "-h", help="Show exploitation hints"),
):
    """
    Look up a CVE and display its full details.
    Automatically saves to your local history.
    """
    cve_upper = cve_id.upper()
    console.print("\n[dim]Fetching data for[/dim] [bold cyan]" + cve_upper + "[/bold cyan][dim]...[/dim]\n")

    try:
        cve = fetch_cve(cve_id)
        save_cve(cve)
    except ValueError as e:
        console.print(Panel(str(e), title="[bold red]Error[/bold red]", border_style="red"))
        raise typer.Exit(code=1)
    except ConnectionError as e:
        console.print(Panel(str(e), title="[bold red]Connection Error[/bold red]", border_style="red"))
        raise typer.Exit(code=1)

    sev_color = SEVERITY_COLORS.get(cve["severity"], "dim")

    info = Text()
    info.append("Published  : ", style="bold")
    info.append(cve["published"] + "\n")
    info.append("Severity   : ", style="bold")
    info.append(cve["severity"] + " (" + str(cve["score"]) + " / 10)\n", style=sev_color)
    info.append("\nDescription:\n", style="bold")
    info.append(cve["description"])

    console.print(Panel(
        info,
        title        = "[bold cyan]" + cve["id"] + "[/bold cyan]",
        border_style = "cyan",
        padding      = (1, 2),
    ))

    if cve["references"]:
        ref_table = Table(title="References", box=box.SIMPLE, show_header=False, border_style="dim")
        ref_table.add_column("URL", style="blue underline")
        for ref in cve["references"]:
            ref_table.add_row(ref)
        console.print(ref_table)

    console.print("[dim]  [+] Saved to history. Run [bold]python cli.py history[/bold] to view.[/dim]")

    if hints:
        console.print(Panel(
            "[yellow]Exploitation hints coming in Phase 2![/yellow]\n"
            "[dim]Run: python cli.py recon " + cve_upper + " to find PoCs right now.[/dim]",
            title        = "[bold yellow]Hints[/bold yellow]",
            border_style = "yellow",
            padding      = (1, 2),
        ))
    else:
        console.print("[dim]  Tip: run [bold]python cli.py recon " + cve_upper + "[/bold] to find PoCs and exploits.\n[/dim]")


@app.command(name="list-cves")
def list_cves():
    """
    Show a table of well-known CVEs you can look up or practice.
    """
    table = Table(
        title        = "Well-Known CVEs — Practice Library",
        box          = box.ROUNDED,
        border_style = "cyan",
        show_lines   = True,
    )
    table.add_column("CVE ID",   style="bold cyan", no_wrap=True)
    table.add_column("Nickname", style="bold white")
    table.add_column("Affects",  style="white")
    table.add_column("Severity", justify="center")
    table.add_column("Score",    justify="center")

    for cve_id, nickname, affects, severity, score in KNOWN_CVES:
        color = SEVERITY_COLORS.get(severity, "dim")
        table.add_row(
            cve_id,
            nickname,
            affects,
            "[" + color + "]" + severity + "[/" + color + "]",
            "[" + color + "]" + score    + "[/" + color + "]",
        )

    console.print()
    console.print(table)
    console.print("\n[dim]  Use: [bold]python cli.py lookup <CVE-ID>[/bold] to fetch full details.\n[/dim]")


@app.command()
def history():
    """
    Show your personal CVE research history.
    Every CVE you look up is saved automatically.
    """
    rows  = get_history()
    stats = get_stats()

    if not rows:
        console.print("\n[dim]  No history yet. Run [bold]python cli.py lookup CVE-2021-44228[/bold] to get started.[/dim]\n")
        return

    table = Table(
        title        = "Your CVE Research History (" + str(stats["total"]) + " total)",
        box          = box.ROUNDED,
        border_style = "cyan",
        show_lines   = True,
    )
    table.add_column("CVE ID",      style="bold cyan", no_wrap=True)
    table.add_column("Severity",    justify="center")
    table.add_column("Score",       justify="center")
    table.add_column("Published",   style="dim")
    table.add_column("Last Lookup", style="dim")
    table.add_column("Notes",       style="yellow")

    for row in rows:
        color = SEVERITY_COLORS.get(row["severity"], "dim")
        table.add_row(
            row["cve_id"],
            "[" + color + "]" + str(row["severity"]) + "[/" + color + "]",
            "[" + color + "]" + str(row["score"])    + "[/" + color + "]",
            row["published"] or "-",
            row["looked_up"],
            row["notes"] if row["notes"] else "[dim]-[/dim]",
        )

    console.print()
    console.print(table)
    console.print(
        "\n[dim]  CRITICAL: " + str(stats["critical"]) +
        "  HIGH: "            + str(stats["high"])     +
        "  MEDIUM: "          + str(stats["medium"])   +
        "  LOW: "             + str(stats["low"])      + "[/dim]\n"
    )


@app.command()
def note(
    cve_id: str = typer.Argument(..., help="CVE ID to add a note to. Example: CVE-2021-44228"),
    text:   str = typer.Argument(..., help="Your note text in quotes."),
):
    """
    Add a personal note to a CVE in your history.

    Example:
        python cli.py note CVE-2021-44228 "Practiced on THM, got RCE via User-Agent"
    """
    saved = add_note(cve_id, text)
    if saved:
        console.print("\n[green][+] Note saved for " + cve_id.upper() + ".[/green]\n")
    else:
        console.print("\n[yellow][!] " + cve_id.upper() + " not in history yet. Run lookup first.[/yellow]\n")


@app.command()
def recon(
    cve_id: str = typer.Argument(..., help="CVE ID to recon. Example: CVE-2021-44228"),
):
    """
    Find PoC exploits, Metasploit modules and writeups for a CVE.
    """
    cve_upper = cve_id.upper()
    console.print("\n[dim]Running recon for[/dim] [bold cyan]" + cve_upper + "[/bold cyan][dim]...[/dim]\n")

    results = run_recon(cve_id)

    if results["metasploit"]:
        msf_text = "\n".join("[green]use " + m + "[/green]" for m in results["metasploit"])
    else:
        msf_text = "[dim]No known Metasploit module for this CVE.[/dim]"

    console.print(Panel(
        msf_text,
        title        = "[bold red]Metasploit Modules[/bold red]",
        border_style = "red",
        padding      = (1, 2),
    ))

    console.print()
    if results["pocs"]:
        poc_table = Table(
            title        = "GitHub PoC Repositories (" + str(len(results["pocs"])) + " found)",
            box          = box.ROUNDED,
            border_style = "green",
            show_lines   = True,
        )
        poc_table.add_column("Repository",  style="bold green")
        poc_table.add_column("Stars",       justify="right", style="yellow")
        poc_table.add_column("Description", style="dim")
        poc_table.add_column("URL",         style="blue underline")

        for poc in results["pocs"]:
            if "error" in poc:
                console.print("[yellow][!] " + poc["error"] + "[/yellow]")
            else:
                poc_table.add_row(poc["name"], str(poc["stars"]), truncate(poc["description"]), poc["url"])
        console.print(poc_table)
    else:
        console.print("[dim]  No PoC repositories found.[/dim]")

    console.print()
    if results["writeups"]:
        wrt_table = Table(
            title        = "Writeups & Analysis",
            box          = box.ROUNDED,
            border_style = "yellow",
            show_lines   = True,
        )
        wrt_table.add_column("Repository",  style="bold yellow")
        wrt_table.add_column("Description", style="dim")
        wrt_table.add_column("URL",         style="blue underline")

        for w in results["writeups"]:
            wrt_table.add_row(w["name"], truncate(w["description"]), w["url"])
        console.print(wrt_table)

    if results["code_results"]:
        console.print()
        code_table = Table(
            title        = "Exploit Scripts Found",
            box          = box.ROUNDED,
            border_style = "cyan",
            show_lines   = True,
        )
        code_table.add_column("File",       style="bold cyan")
        code_table.add_column("Repository", style="dim")
        code_table.add_column("URL",        style="blue underline")

        for c in results["code_results"]:
            code_table.add_row(c["name"], c["repo"], c["url"])
        console.print(code_table)

    console.print("\n[dim]  Tip: run [bold]python cli.py resources " + cve_upper + "[/bold] to find practice rooms.\n[/dim]")


@app.command()
def resources(
    cve_id: str = typer.Argument(..., help="CVE ID to find resources for. Example: CVE-2021-44228"),
):
    """
    Find TryHackMe rooms, HTB machines, VulnHub VMs and ExploitDB entries for a CVE.
    """
    cve_upper = cve_id.upper()
    console.print("\n[dim]Finding resources for[/dim] [bold cyan]" + cve_upper + "[/bold cyan][dim]...[/dim]\n")

    results = get_resources(cve_id)

    if not results["found"]:
        console.print(Panel(
            "[yellow]No curated resources found for " + cve_upper + ".[/yellow]\n\n"
            "[dim]Try searching manually:[/dim]\n"
            "[blue underline]https://tryhackme.com/hacktivities?q=" + cve_upper + "[/blue underline]\n"
            "[blue underline]https://www.exploit-db.com/search?cve=" + cve_id[4:] + "[/blue underline]\n"
            "[blue underline]https://github.com/search?q=" + cve_upper + "[/blue underline]",
            title        = "[bold yellow]Resources[/bold yellow]",
            border_style = "yellow",
            padding      = (1, 2),
        ))
        return

    if results["thm"]:
        thm_table = Table(title="TryHackMe Rooms", box=box.ROUNDED, border_style="green", show_lines=True)
        thm_table.add_column("Room",       style="bold green")
        thm_table.add_column("Difficulty", justify="center")
        thm_table.add_column("Access",     justify="center")
        thm_table.add_column("URL",        style="blue underline")
        for room in results["thm"]:
            access = "[green]FREE[/green]" if room["free"] else "[yellow]Subscription[/yellow]"
            thm_table.add_row(room["name"], room["difficulty"], access, room["url"])
        console.print(thm_table)
        console.print()

    if results["htb"]:
        htb_table = Table(title="HackTheBox Machines", box=box.ROUNDED, border_style="red", show_lines=True)
        htb_table.add_column("Machine",    style="bold red")
        htb_table.add_column("Difficulty", justify="center")
        htb_table.add_column("Access",     justify="center")
        htb_table.add_column("URL",        style="blue underline")
        for machine in results["htb"]:
            access = "[green]FREE[/green]" if machine["free"] else "[yellow]VIP[/yellow]"
            htb_table.add_row(machine["name"], machine["difficulty"], access, machine["url"])
        console.print(htb_table)
        console.print()

    if results["vulnhub"]:
        vhl_table = Table(title="VulnHub (Always Free)", box=box.ROUNDED, border_style="cyan", show_lines=True)
        vhl_table.add_column("VM Name", style="bold cyan")
        vhl_table.add_column("URL",     style="blue underline")
        for vm in results["vulnhub"]:
            vhl_table.add_row(vm["name"], vm["url"])
        console.print(vhl_table)
        console.print()

    if results["exploitdb"]:
        edb_table = Table(title="ExploitDB Entries", box=box.ROUNDED, border_style="yellow", show_lines=True)
        edb_table.add_column("EDB ID", style="bold yellow", no_wrap=True)
        edb_table.add_column("Title",  style="white")
        edb_table.add_column("URL",    style="blue underline")
        for edb in results["exploitdb"]:
            edb_table.add_row("EDB-" + edb["id"], edb["title"], edb["url"])
        console.print(edb_table)
        console.print()

    if results["youtube"]:
        yt_table = Table(title="YouTube Walkthroughs", box=box.ROUNDED, border_style="red", show_lines=True)
        yt_table.add_column("Title", style="bold white")
        yt_table.add_column("URL",   style="blue underline")
        for yt in results["youtube"]:
            yt_table.add_row(yt["title"], yt["url"])
        console.print(yt_table)
        console.print()

    console.print("[dim]  Tip: run [bold]python cli.py note-gen " + cve_upper + "[/bold] to generate markdown notes.\n[/dim]")


@app.command(name="note-gen")
def note_gen(
    cve_id: str = typer.Argument(..., help="CVE ID to generate notes for. Example: CVE-2021-44228"),
):
    """
    Generate a structured markdown notes template for a CVE.
    Saved to the /notes folder in your project directory.

    Example:
        python cli.py note-gen CVE-2021-44228
    """
    cve_upper = cve_id.upper()
    console.print("\n[dim]Generating notes for[/dim] [bold cyan]" + cve_upper + "[/bold cyan][dim]...[/dim]\n")

    try:
        console.print("[dim]  Fetching CVE data...[/dim]")
        cve = fetch_cve(cve_id)

        console.print("[dim]  Running recon...[/dim]")
        recon_results = run_recon(cve_id)

        console.print("[dim]  Finding resources...[/dim]")
        resource_results = get_resources(cve_id)

        console.print("[dim]  Writing notes file...[/dim]\n")
        path = generate_note(cve, recon_results, resource_results)

    except (ValueError, ConnectionError) as e:
        console.print(Panel(str(e), title="[bold red]Error[/bold red]", border_style="red"))
        raise typer.Exit(code=1)

    console.print(Panel(
        "[green]Notes generated successfully![/green]\n\n"
        "[dim]Saved to:[/dim] [bold]" + path + "[/bold]\n\n"
        "[dim]Open it in VS Code, Obsidian, or any markdown editor.\n"
        "Fill in the 'My Notes' section as you practice.[/dim]",
        title        = "[bold green]Done[/bold green]",
        border_style = "green",
        padding      = (1, 2),
    ))


# ── Banner ────────────────────────────────────────────────────────────────────

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    CveScaf — Your personal CVE research and lab assistant.
    """
    if ctx.invoked_subcommand is None:
        ascii_art = pyfiglet.figlet_format("CveScaf", font="slant")
        banner = Text()
        banner.append(ascii_art, style="bold cyan")
        banner.append("  Your personal CVE research & lab assistant\n\n", style="dim")
        banner.append("  Commands:\n", style="bold")
        banner.append("    lookup    ", style="cyan")
        banner.append("->  Look up a CVE by ID\n")
        banner.append("    recon     ", style="cyan")
        banner.append("->  Find PoCs, Metasploit modules and writeups\n")
        banner.append("    resources ", style="cyan")
        banner.append("->  Find THM rooms, HTB machines, VulnHub VMs\n")
        banner.append("    note-gen  ", style="cyan")
        banner.append("->  Generate markdown notes for a CVE\n")
        banner.append("    list-cves ", style="cyan")
        banner.append("->  Show the practice library\n")
        banner.append("    history   ", style="cyan")
        banner.append("->  View your research history\n")
        banner.append("    note      ", style="cyan")
        banner.append("->  Add a quick note to a CVE\n")

        console.print(Panel(banner, border_style="cyan", padding=(1, 2)))
        console.print("[dim]  Run [bold]python cli.py --help[/bold] for full usage.\n[/dim]")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()