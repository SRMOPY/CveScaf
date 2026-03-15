"""
core/reporter.py
----------------
Generates a clean, professional PDF report for a CVE.
Includes CVE details, PoCs, Metasploit modules, and practice resources.

Reports are saved to a /reports folder in your project directory.

Requirements:
    pip install reportlab

Usage (standalone):
    python core/reporter.py CVE-2021-44228

Usage (from cli.py):
    from core.reporter import generate_report
    path = generate_report(cve, recon_results, resource_results)
"""

import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ── Reports folder ────────────────────────────────────────────────────────────
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")

# ── Color palette (matching CveScaf theme) ────────────────────────────────────
BLACK      = colors.HexColor("#0a0a0a")
DARK       = colors.HexColor("#111111")
DARK2      = colors.HexColor("#1a1a1a")
RED        = colors.HexColor("#ff2222")
RED_DIM    = colors.HexColor("#991111")
WHITE      = colors.HexColor("#ffffff")
GRAY       = colors.HexColor("#e0e0e0")
GRAY_DIM   = colors.HexColor("#666666")
GREEN      = colors.HexColor("#00ff88")
YELLOW     = colors.HexColor("#ffcc00")
CYAN       = colors.HexColor("#00ccff")

# ── Severity colors ───────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#ff2222"),
    "HIGH":     colors.HexColor("#ff6400"),
    "MEDIUM":   colors.HexColor("#ffcc00"),
    "LOW":      colors.HexColor("#00ff88"),
    "UNKNOWN":  colors.HexColor("#666666"),
}

# ── Styles ────────────────────────────────────────────────────────────────────
def make_styles():
    return {
        "title": ParagraphStyle(
            "title",
            fontName    = "Helvetica-Bold",
            fontSize    = 28,
            textColor   = WHITE,
            spaceAfter  = 4,
            alignment   = TA_LEFT,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            fontName    = "Helvetica",
            fontSize    = 11,
            textColor   = GRAY_DIM,
            spaceAfter  = 2,
            alignment   = TA_LEFT,
        ),
        "section": ParagraphStyle(
            "section",
            fontName    = "Helvetica-Bold",
            fontSize    = 11,
            textColor   = RED,
            spaceBefore = 14,
            spaceAfter  = 6,
            alignment   = TA_LEFT,
        ),
        "body": ParagraphStyle(
            "body",
            fontName    = "Helvetica",
            fontSize    = 9,
            textColor   = GRAY,
            spaceAfter  = 6,
            leading     = 14,
            alignment   = TA_LEFT,
        ),
        "mono": ParagraphStyle(
            "mono",
            fontName    = "Courier",
            fontSize    = 9,
            textColor   = GREEN,
            spaceAfter  = 4,
            leading     = 13,
            alignment   = TA_LEFT,
        ),
        "mono_dim": ParagraphStyle(
            "mono_dim",
            fontName    = "Courier",
            fontSize    = 8,
            textColor   = GRAY_DIM,
            spaceAfter  = 4,
            leading     = 12,
            alignment   = TA_LEFT,
        ),
        "footer": ParagraphStyle(
            "footer",
            fontName    = "Helvetica",
            fontSize    = 8,
            textColor   = GRAY_DIM,
            alignment   = TA_CENTER,
        ),
        "tag": ParagraphStyle(
            "tag",
            fontName    = "Helvetica-Bold",
            fontSize    = 8,
            textColor   = WHITE,
            alignment   = TA_CENTER,
        ),
    }


def ensure_reports_dir():
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)


def get_report_path(cve_id: str) -> str:
    filename = cve_id.upper().replace("-", "_") + "_report.pdf"
    return os.path.join(REPORTS_DIR, filename)


def _header_footer(canvas, doc):
    """Draws the background, header and footer on every page."""
    canvas.saveState()
    width, height = A4

    # Dark background — full page
    canvas.setFillColor(BLACK)
    canvas.rect(0, 0, width, height, fill=1, stroke=0)

    # Header bar
    canvas.setFillColor(DARK)
    canvas.rect(0, height - 18*mm, width, 18*mm, fill=1, stroke=0)

    # Red accent line under header
    canvas.setFillColor(RED)
    canvas.rect(0, height - 18*mm - 1, width, 1.5, fill=1, stroke=0)

    # Header text
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(15*mm, height - 12*mm, "CveScaf")
    canvas.setFillColor(GRAY_DIM)
    canvas.setFont("Helvetica", 9)
    canvas.drawString(15*mm + 42, height - 12*mm, "CVE Research Report")

    # Page number
    canvas.setFillColor(GRAY_DIM)
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(width - 15*mm, height - 12*mm, f"Page {doc.page}")

    # Footer
    canvas.setFillColor(DARK)
    canvas.rect(0, 0, width, 10*mm, fill=1, stroke=0)
    canvas.setFillColor(RED)
    canvas.rect(0, 10*mm, width, 0.5, fill=1, stroke=0)
    canvas.setFillColor(GRAY_DIM)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(15*mm, 3.5*mm, "Generated by CveScaf — github.com/SRMOPY/CveScaf")
    canvas.drawRightString(
        width - 15*mm, 3.5*mm,
        datetime.now().strftime("%Y-%m-%d %H:%M")
    )

    canvas.restoreState()


def generate_report(
    cve:       dict,
    recon:     dict = None,
    resources: dict = None,
) -> str:
    """
    Generates a PDF report for a CVE.

    Args:
        cve (dict):       CVE data from fetcher.fetch_cve()
        recon (dict):     Recon results from recon.run_recon()
        resources (dict): Resource results from resources.get_resources()

    Returns:
        str: Full path to the saved PDF report
    """
    ensure_reports_dir()

    cve_id      = cve["id"]
    report_path = get_report_path(cve_id)
    styles      = make_styles()

    doc = SimpleDocTemplate(
        report_path,
        pagesize     = A4,
        leftMargin   = 15*mm,
        rightMargin  = 15*mm,
        topMargin    = 22*mm,
        bottomMargin = 14*mm,
    )

    story = []
    width = A4[0] - 30*mm  # usable width

    # ── Cover section ─────────────────────────────────────────────────────────
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph(cve_id, styles["title"]))
    story.append(Spacer(1, 8*mm))

    sev_color = SEVERITY_COLORS.get(cve["severity"], GRAY_DIM)
    story.append(Paragraph(
        '<font color="' + sev_color.hexval() + '">&#9632; ' + cve["severity"] + ' — ' + str(cve["score"]) + ' / 10</font>',
        styles["subtitle"]
    ))
    story.append(Paragraph(
        '<font color="' + GRAY_DIM.hexval() + '">Published: ' + cve["published"] + '</font>',
        styles["subtitle"]
    ))
    story.append(Spacer(1, 4*mm))
    story.append(HRFlowable(width=width, color=RED_DIM, thickness=0.5))
    story.append(Spacer(1, 3*mm))

    # ── Description ───────────────────────────────────────────────────────────
    story.append(Paragraph("// Description", styles["section"]))
    story.append(Paragraph(cve["description"], styles["body"]))

    # ── References ────────────────────────────────────────────────────────────
    if cve.get("references"):
        story.append(Paragraph("// References", styles["section"]))
        for ref in cve["references"]:
            story.append(Paragraph(f'<font color="#00ccff">{ref}</font>', styles["mono_dim"]))

    story.append(Spacer(1, 3*mm))
    story.append(HRFlowable(width=width, color=DARK2, thickness=0.5))

    # ── Metasploit modules ────────────────────────────────────────────────────
    story.append(Paragraph("// Metasploit Modules", styles["section"]))
    if recon and recon.get("metasploit"):
        for mod in recon["metasploit"]:
            story.append(Paragraph("use " + mod, styles["mono"]))
            story.append(Paragraph("set RHOSTS &lt;TARGET_IP&gt;", styles["mono_dim"]))
            story.append(Paragraph("run", styles["mono_dim"]))
            story.append(Spacer(1, 2*mm))
    else:
        story.append(Paragraph("No known Metasploit module for this CVE.", styles["body"]))

    # ── PoC exploits ──────────────────────────────────────────────────────────
    story.append(Paragraph("// PoC Exploits (GitHub)", styles["section"]))
    if recon and recon.get("pocs"):
        poc_data = [["Repository", "Stars", "URL"]]
        for poc in recon["pocs"]:
            if "error" not in poc:
                poc_data.append([
                    poc["name"],
                    str(poc["stars"]),
                    poc["url"][:55] + "..." if len(poc["url"]) > 55 else poc["url"],
                ])

        if len(poc_data) > 1:
            poc_table = Table(poc_data, colWidths=[55*mm, 15*mm, width - 70*mm])
            poc_table.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0),  DARK2),
                ("TEXTCOLOR",    (0, 0), (-1, 0),  RED),
                ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
                ("FONTSIZE",     (0, 0), (-1, 0),  8),
                ("FONTNAME",     (0, 1), (-1, -1), "Courier"),
                ("FONTSIZE",     (0, 1), (-1, -1), 7),
                ("TEXTCOLOR",    (0, 1), (-1, -1), GRAY),
                ("TEXTCOLOR",    (2, 1), (2, -1),  CYAN),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [DARK, colors.HexColor("#0f0f0f")]),
                ("GRID",         (0, 0), (-1, -1), 0.3, colors.HexColor("#2a2a2a")),
                ("LEFTPADDING",  (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING",   (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
            ]))
            story.append(poc_table)
    else:
        story.append(Paragraph("No PoC repositories found.", styles["body"]))

    story.append(Spacer(1, 3*mm))
    story.append(HRFlowable(width=width, color=DARK2, thickness=0.5))

    # ── Practice resources ────────────────────────────────────────────────────
    story.append(Paragraph("// Practice Resources", styles["section"]))

    if resources and resources.get("found"):
        res_data = [["Platform", "Name", "Access", "URL"]]

        for room in resources.get("thm", []):
            res_data.append(["THM", room["name"], "FREE" if room["free"] else "Sub", room["url"]])
        for m in resources.get("htb", []):
            res_data.append(["HTB", m["name"], "FREE" if m["free"] else "VIP", m["url"]])
        for vm in resources.get("vulnhub", []):
            res_data.append(["VulnHub", vm["name"], "FREE", vm["url"]])
        for edb in resources.get("exploitdb", []):
            res_data.append(["EDB", "EDB-" + edb["id"], "-", edb["url"]])
        for yt in resources.get("youtube", []):
            res_data.append(["YouTube", yt["title"][:40], "-", yt["url"]])

        if len(res_data) > 1:
            res_table = Table(res_data, colWidths=[18*mm, 45*mm, 15*mm, width - 78*mm])
            res_table.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0),  DARK2),
                ("TEXTCOLOR",     (0, 0), (-1, 0),  RED),
                ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, 0),  8),
                ("FONTNAME",      (0, 1), (-1, -1), "Courier"),
                ("FONTSIZE",      (0, 1), (-1, -1), 7),
                ("TEXTCOLOR",     (0, 1), (-1, -1), GRAY),
                ("TEXTCOLOR",     (3, 1), (3, -1),  CYAN),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [DARK, colors.HexColor("#0f0f0f")]),
                ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#2a2a2a")),
                ("LEFTPADDING",   (0, 0), (-1, -1), 4),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(res_table)
    else:
        story.append(Paragraph("No curated resources found for this CVE.", styles["body"]))

    story.append(Spacer(1, 3*mm))
    story.append(HRFlowable(width=width, color=DARK2, thickness=0.5))

    # ── Notes section (blank for user to fill) ────────────────────────────────
    story.append(Paragraph("// My Notes", styles["section"]))
    story.append(Paragraph("What I learned:", styles["body"]))
    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width=width, color=DARK2, thickness=0.3))
    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width=width, color=DARK2, thickness=0.3))
    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width=width, color=DARK2, thickness=0.3))
    story.append(Spacer(1, 5*mm))
    story.append(Paragraph("Flags captured:", styles["body"]))
    story.append(Paragraph("user.txt: ___________________________", styles["mono_dim"]))
    story.append(Paragraph("root.txt: ___________________________", styles["mono_dim"]))

    # ── Build PDF ─────────────────────────────────────────────────────────────
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)

    return report_path


# ── Quick test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from core.fetcher import fetch_cve
    from core.recon import run_recon
    from core.resources import get_resources

    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    print("Generating report for " + cve_id + "...")

    cve       = fetch_cve(cve_id)
    recon     = run_recon(cve_id)
    resources = get_resources(cve_id)
    path      = generate_report(cve, recon, resources)

    print("[+] Report saved to: " + path)