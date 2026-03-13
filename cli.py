"""
cli.py
------
Main entry point for CVE Scaffolder.
Ties all modules together into a clean CLI experience.

Usage:
    python cli.py lookup CVE-2021-44228
    python cli.py lookup CVE-2017-0144 --hints
    python cli.py list-cves
    python cli.py --help

Requirements:
    pip install typer rich
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

# Our own modules
from fetcher import fetch_cve

# ── App setup ────────────────────────────────────────────────────────────────

app     = typer.Typer(
    name            = "cvescaffold",
    help            = "CVE-to-Lab Scaffolder — Look up CVEs and build your attack lab.",
    add_completion  = False,
)
console = Console()

# ── Severity color map (for rich) ────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "UNKNOWN":  "dim",
}

# ── A few example CVEs to show in list-cves ──────────────────────────────────

KNOWN_CVES = [
    ("CVE-2021-44228", "Log4Shell",    "Apache Log4j2",  "CRITICAL", "10.0"),
    ("CVE-2017-7494",  "SambaCry",     "Samba",          "CRITICAL", "9.8"),
    ("CVE-2014-6271",  "Shellshock",   "Bash",           "CRITICAL", "9.8"),
    ("CVE-2021-3156",  "Baron Samedit","sudo",           "HIGH",     "7.8"),
    ("CVE-2019-11043", "PHP-FPM RCE",  "PHP-FPM/Nginx",  "CRITICAL", "9.8"),
    ("CVE-2019-0708",  "BlueKeep",     "Windows RDP",    "CRITICAL", "9.8"),
    ("CVE-2017-0144",  "EternalBlue",  "Windows SMB",    "HIGH",     "8.8"),
    ("CVE-2020-1472",  "Zerologon",    "Windows Netlogon","CRITICAL","10.0"),
]


# ── Commands ─────────────────────────────────────────────────────────────────

@app.command()
def lookup(
    cve_id: str = typer.Argument(..., help="The CVE ID to look up. Example: CVE-2021-44228"),
    hints:  bool = typer.Option(False, "--hints", "-h", help="Show exploitation hints (coming in Phase 2)"),
):
    """
    Look up a CVE and display its full details.

    Examples:\n
        python cli.py lookup CVE-2021-44228\n
        python cli.py lookup CVE-2014-6271 --hints
    """

    console.print(f"\n[dim]Fetching data for[/dim] [bold cyan]{cve_id.upper()}[/bold cyan][dim]...[/dim]\n")

    # ── Fetch CVE data ────────────────────────────────────────────────────────
    try:
        cve = fetch_cve(cve_id)
    except ValueError as e:
        console.print(Panel(
            f"[red]{e}[/red]",
            title="[bold red]Error[/bold red]",
            border_style="red",
        ))
        raise typer.Exit(code=1)
    except ConnectionError as e:
        console.print(Panel(
            f"[red]{e}[/red]\n[dim]Check your internet connection and try again.[/dim]",
            title="[bold red]Connection Error[/bold red]",
            border_style="red",
        ))
        raise typer.Exit(code=1)

    # ── Severity styling ──────────────────────────────────────────────────────
    sev_color = SEVERITY_COLORS.get(cve["severity"], "dim")
    sev_label = f"[{sev_color}]{cve['severity']} ({cve['score']} / 10)[/{sev_color}]"

    # ── Main info panel ───────────────────────────────────────────────────────
    info = Text()
    info.append("Published  : ", style="bold")
    info.append(f"{cve['published']}\n")
    info.append("Severity   : ", style="bold")
    info.append(f"{cve['severity']} ({cve['score']} / 10)\n", style=sev_color)
    info.append("\nDescription:\n", style="bold")
    info.append(cve["description"])

    console.print(Panel(
        info,
        title=f"[bold cyan]{cve['id']}[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))

    # ── References table ──────────────────────────────────────────────────────
    if cve["references"]:
        table = Table(
            title       = "References",
            box         = box.SIMPLE,
            show_header = False,
            border_style= "dim",
        )
        table.add_column("URL", style="blue underline")
        for ref in cve["references"]:
            table.add_row(ref)
        console.print(table)

    # ── Hints notice ─────────────────────────────────────────────────────────
    if hints:
        console.print(Panel(
            "[yellow]Exploitation hints are coming in Phase 2![/yellow]\n"
            "[dim]We'll pull live PoCs from GitHub and match Metasploit modules automatically.[/dim]",
            title="[bold yellow]Hints[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        ))
    else:
        console.print(
            "[dim]  Tip: run with [/dim][bold]--hints[/bold][dim] flag to see exploitation hints (coming soon!)[/dim]\n"
        )


@app.command(name="list-cves")
def list_cves():
    """
    Show a table of well-known CVEs you can look up or practice.
    """

    table = Table(
        title       = "Well-Known CVEs — Practice Library",
        box         = box.ROUNDED,
        border_style= "cyan",
        show_lines  = True,
    )

    table.add_column("CVE ID",      style="bold cyan",  no_wrap=True)
    table.add_column("Nickname",    style="bold white")
    table.add_column("Affects",     style="white")
    table.add_column("Severity",    justify="center")
    table.add_column("Score",       justify="center")

    for cve_id, nickname, affects, severity, score in KNOWN_CVES:
        color = SEVERITY_COLORS.get(severity, "dim")
        table.add_row(
            cve_id,
            nickname,
            affects,
            f"[{color}]{severity}[/{color}]",
            f"[{color}]{score}[/{color}]",
        )

    console.print()
    console.print(table)
    console.print(
        "\n[dim]  Use:[/dim] [bold]python cli.py lookup <CVE-ID>[/bold] "
        "[dim]to fetch full details on any of these.\n[/dim]"
    )


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    CVE Scaffolder — Your personal CVE research and lab assistant.
    """
    if ctx.invoked_subcommand is None:
        # Show banner when no command is given
        banner = Text()
        banner.append("  CVE Scaffolder\n", style="bold cyan")
        banner.append("  Your personal CVE research & lab assistant\n\n", style="dim")
        banner.append("  Commands:\n", style="bold")
        banner.append("    lookup    ", style="cyan")
        banner.append("→  Look up a CVE by ID\n")
        banner.append("    list-cves ", style="cyan")
        banner.append("→  Show the practice library\n")

        console.print(Panel(
            banner,
            border_style = "cyan",
            padding      = (1, 2),
        ))
        console.print("[dim]  Run [bold]python cli.py --help[/bold] for full usage.\n[/dim]")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()