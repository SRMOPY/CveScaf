"""
web/app.py
----------
Flask backend for CveScaf Web UI.

Usage:
    cd CveScaf
    python web/app.py

Then open: http://localhost:5000
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify, redirect, url_for
from core.fetcher import fetch_cve
from core.recon import run_recon
from core.resources import get_resources
from core.notes import generate_note
from core.db import init_db, save_cve, get_history, get_stats, add_note, get_cve_from_history
from core.searcher import search_cves
from core.reporter import generate_report

app = Flask(__name__)
init_db()

KNOWN_CVES = [
    {"id": "CVE-2021-44228", "nickname": "Log4Shell",     "affects": "Apache Log4j2",    "severity": "CRITICAL", "score": "10.0"},
    {"id": "CVE-2017-7494",  "nickname": "SambaCry",      "affects": "Samba",            "severity": "CRITICAL", "score": "9.8"},
    {"id": "CVE-2014-6271",  "nickname": "Shellshock",    "affects": "Bash",             "severity": "CRITICAL", "score": "9.8"},
    {"id": "CVE-2021-3156",  "nickname": "Baron Samedit", "affects": "sudo",             "severity": "HIGH",     "score": "7.8"},
    {"id": "CVE-2019-11043", "nickname": "PHP-FPM RCE",   "affects": "PHP-FPM/Nginx",    "severity": "CRITICAL", "score": "9.8"},
    {"id": "CVE-2019-0708",  "nickname": "BlueKeep",      "affects": "Windows RDP",      "severity": "CRITICAL", "score": "9.8"},
    {"id": "CVE-2017-0144",  "nickname": "EternalBlue",   "affects": "Windows SMB",      "severity": "HIGH",     "score": "8.8"},
    {"id": "CVE-2020-1472",  "nickname": "Zerologon",     "affects": "Windows Netlogon", "severity": "CRITICAL", "score": "10.0"},
]


@app.route("/")
def index():
    stats   = get_stats()
    history = get_history(limit=5)
    return render_template("index.html", stats=stats, history=[dict(r) for r in history])


@app.route("/lookup", methods=["GET", "POST"])
def lookup():
    if request.method == "POST":
        cve_id = request.form.get("cve_id", "").strip().upper()
        if not cve_id:
            return render_template("lookup.html", error="Please enter a CVE ID.")
        return redirect(url_for("cve_detail", cve_id=cve_id))
    return render_template("lookup.html")


@app.route("/cve/<cve_id>")
def cve_detail(cve_id):
    cve_id = cve_id.strip().upper()
    try:
        cve = fetch_cve(cve_id)
        save_cve(cve)
    except (ValueError, ConnectionError) as e:
        return render_template("lookup.html", error=str(e))

    recon_data    = run_recon(cve_id)
    resource_data = get_resources(cve_id)
    entry         = get_cve_from_history(cve_id)

    return render_template(
        "cve.html",
        cve        = cve,
        recon      = recon_data,
        resources  = resource_data,
        saved_note = dict(entry)["notes"] if entry else "",
    )


@app.route("/search")
def search():
    keyword = request.args.get("q", "").strip()
    if not keyword:
        return render_template("search.html", results=[], keyword="", error=None)
    try:
        results = search_cves(keyword, limit=15)
        return render_template("search.html", results=results, keyword=keyword, error=None)
    except (ValueError, ConnectionError) as e:
        return render_template("search.html", results=[], keyword=keyword, error=str(e))


@app.route("/history")
def history():
    rows  = get_history(limit=50)
    stats = get_stats()
    return render_template("history.html", history=[dict(r) for r in rows], stats=stats)


@app.route("/library")
def library():
    return render_template("library.html", cves=KNOWN_CVES)


@app.route("/api/note", methods=["POST"])
def api_add_note():
    data   = request.get_json()
    cve_id = data.get("cve_id", "").upper()
    text   = data.get("note", "")
    saved  = add_note(cve_id, text)
    return jsonify({"success": saved})


@app.route("/api/note-gen/<cve_id>")
def api_note_gen(cve_id):
    try:
        cve       = fetch_cve(cve_id)
        recon     = run_recon(cve_id)
        resources = get_resources(cve_id)
        path      = generate_note(cve, recon, resources)
        return jsonify({"success": True, "path": path})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/report/<cve_id>")
def api_report(cve_id):
    try:
        cve       = fetch_cve(cve_id)
        recon     = run_recon(cve_id)
        resources = get_resources(cve_id)
        path      = generate_report(cve, recon, resources)
        return jsonify({"success": True, "path": path})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


if __name__ == "__main__":
    print("\n  CveScaf Web UI")
    print("  Running at: http://localhost:5000\n")
    app.run(debug=True, port=5000)