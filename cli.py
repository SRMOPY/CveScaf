"""
cli.py
------
Main entry point for CVE Scaffolder.

Usage:
    python cli.py lookup CVE-2021-44228
    python cli.py recon CVE-2021-44228
    python cli.py list-cves
    python cli.py history
    python cli.py note CVE-2021-44228 "my note here"
    python cli.py --help

Requirements:
    pip install typer rich requests
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

from fetcher import fetch_cve
from db import init_db, save_cve, get_history, get_stats, add_note
from recon import run_recon

# Initialize database on startup
init_db()

# ── App setup ─────────────────────────────────────────────────────────────────

app = typer.Typer(
    name           = "cvescaffold",
    help           = "CVE-to-Lab Scaffolder — Look up CVEs and build your attack lab.",
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
    console.print("\n[dim]Fetching data for[/dim] [bold cyan]" + cve_id.upper() + "[/bold cyan][dim]...[/dim]\n")

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

    console.print(Panel(info, title="[bold cyan]" + cve["id"] + "[/bold cyan]", border_style="cyan", padding=(1, 2)))

    if cve["references"]:
        table = Table(title="References", box=box.SIMPLE, show_header=False, border_style="dim")
        table.add_column("URL", style="blue underline")
        for ref in cve["references"]:
            table.add_row(ref)
        console.print(table)

    console.print("[dim]  [+] Saved to history. Run [bold]python cli.py history[/bold] to view.[/dim]")

    if hints:
        console.print(Panel(
            "[yellow]Exploitation hints coming in Phase 2![/yellow]\n"
            "[dim]Run: python cli.py recon " + cve_id.upper() + " to find PoCs right now.[/dim]",
            title="[bold yellow]Hints[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        ))
    else:
        console.print("[dim]  Tip: run [bold]python cli.py recon " + cve_id.upper() + "[/bold] to find PoCs and exploits.\n[/dim]")


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
            "[" + color + "]" + score + "[/" + color + "]",
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
            "[" + color + "]" + str(row["score"]) + "[/" + color + "]",
            row["published"] or "-",
            row["looked_up"],
            row["notes"] if row["notes"] else "[dim]-[/dim]",
        )

    console.print()
    console.print(table)
    console.print(
        "\n[dim]  CRITICAL: " + str(stats["critical"]) +
        "  HIGH: " + str(stats["high"]) +
        "  MEDIUM: " + str(stats["medium"]) +
        "  LOW: " + str(stats["low"]) + "[/dim]\n"
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
    console.print("\n[dim]Running recon for[/dim] [bold cyan]" + cve_id.upper() + "[/bold cyan][dim]...[/dim]\n")

    results = run_recon(cve_id)

    # ── Metasploit modules ────────────────────────────────────────────────────
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

    # ── PoC repositories ──────────────────────────────────────────────────────
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
                desc = poc["description"]
                short_desc = (desc[:60] + "...") if len(desc) > 60 else desc
                poc_table.add_row(poc["name"], str(poc["stars"]), short_desc, poc["url"])

        console.print(poc_table)
    else:
        console.print("[dim]  No PoC repositories found.[/dim]")

    # ── Writeups ──────────────────────────────────────────────────────────────
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
            desc = w["description"]
            short_desc = (desc[:60] + "...") if len(desc) > 60 else desc
            wrt_table.add_row(w["name"], short_desc, w["url"])

        console.print(wrt_table)

    # ── Code results ──────────────────────────────────────────────────────────
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

    console.print("\n[dim]  Tip: run [bold]python cli.py lookup " + cve_id.upper() + "[/bold] to see full CVE details.[/dim]\n")


# ── Banner ────────────────────────────────────────────────────────────────────

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    CVE Scaffolder — Your personal CVE research and lab assistant.
    """
    if ctx.invoked_subcommand is None:
        banner = Text()
        banner.append("  CVE Scaffolder\n",                               style="bold cyan")
        banner.append("  Your personal CVE research & lab assistant\n\n", style="dim")
        banner.append("  Commands:\n", style="bold")
        banner.append("    lookup    ", style="cyan")
        banner.append("->  Look up a CVE by ID\n")
        banner.append("    recon     ", style="cyan")
        banner.append("->  Find PoCs, Metasploit modules and writeups\n")
        banner.append("    list-cves ", style="cyan")
        banner.append("->  Show the practice library\n")
        banner.append("    history   ", style="cyan")
        banner.append("->  View your research history\n")
        banner.append("    note      ", style="cyan")
        banner.append("->  Add a note to a CVE\n")

        console.print(Panel(banner, border_style="cyan", padding=(1, 2)))
        console.print("[dim]  Run [bold]python cli.py --help[/bold] for full usage.\n[/dim]")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()