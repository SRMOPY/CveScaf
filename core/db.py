"""
db.py
-----
Local SQLite database for CVE Scaffolder.
Saves every CVE you look up so you have a personal research history.

No setup needed — the database file is created automatically
the first time you run the tool.

Database file: cvescaffold.db (local, never uploaded anywhere)
"""

import sqlite3
import os
from datetime import datetime

# ── Database location ─────────────────────────────────────────────────────────
# Stored in the same folder as this script
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvescaffold.db")


def get_connection():
    """
    Returns a connection to the local SQLite database.
    Creates the database file if it doesn't exist yet.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Lets us access columns by name
    return conn


def init_db():
    """
    Creates the database tables if they don't exist yet.
    Safe to call every time the tool starts — won't overwrite existing data.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # ── CVE history table ─────────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id      TEXT NOT NULL,
            severity    TEXT,
            score       TEXT,
            description TEXT,
            published   TEXT,
            looked_up   TEXT NOT NULL,
            notes       TEXT DEFAULT ''
        )
    """)

    conn.commit()
    conn.close()


def save_cve(cve: dict) -> None:
    """
    Saves a CVE lookup to the local database.
    Called automatically every time you run 'lookup'.

    Args:
        cve (dict): CVE data returned by fetcher.fetch_cve()
    """
    conn   = get_connection()
    cursor = conn.cursor()

    # Check if we've looked this one up before
    cursor.execute("SELECT id FROM cve_history WHERE cve_id = ?", (cve["id"],))
    existing = cursor.fetchone()

    if existing:
        # Update the timestamp — so we know when we last looked it up
        cursor.execute("""
            UPDATE cve_history
            SET looked_up = ?, severity = ?, score = ?, description = ?, published = ?
            WHERE cve_id = ?
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M"),
            cve["severity"],
            str(cve["score"]),
            cve["description"],
            cve["published"],
            cve["id"],
        ))
    else:
        # First time seeing this CVE — insert it
        cursor.execute("""
            INSERT INTO cve_history (cve_id, severity, score, description, published, looked_up)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            cve["id"],
            cve["severity"],
            str(cve["score"]),
            cve["description"],
            cve["published"],
            datetime.now().strftime("%Y-%m-%d %H:%M"),
        ))

    conn.commit()
    conn.close()


def get_history(limit: int = 20) -> list:
    """
    Returns your most recent CVE lookups.

    Args:
        limit (int): How many records to return (default: 20)

    Returns:
        list of sqlite3.Row objects (access like dicts)
    """
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT cve_id, severity, score, published, looked_up, notes
        FROM cve_history
        ORDER BY looked_up DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()
    return rows


def get_cve_from_history(cve_id: str) -> sqlite3.Row | None:
    """
    Looks up a specific CVE from your local history.
    Returns None if you've never looked it up before.

    Args:
        cve_id (str): e.g. 'CVE-2021-44228'

    Returns:
        sqlite3.Row or None
    """
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM cve_history WHERE cve_id = ?
    """, (cve_id.upper(),))

    row = cursor.fetchone()
    conn.close()
    return row


def add_note(cve_id: str, note: str) -> bool:
    """
    Adds or updates a personal note for a CVE.
    Great for saving your own exploitation tips or progress.

    Args:
        cve_id (str): e.g. 'CVE-2021-44228'
        note (str): Your note text

    Returns:
        bool: True if saved, False if CVE not found in history
    """
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE cve_history SET notes = ? WHERE cve_id = ?
    """, (note, cve_id.upper()))

    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated


def clear_history() -> int:
    """
    Clears all CVE history from the database.
    Returns the number of records deleted.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM cve_history")
    count = cursor.fetchone()[0]

    cursor.execute("DELETE FROM cve_history")
    conn.commit()
    conn.close()
    return count


def get_stats() -> dict:
    """
    Returns some fun stats about your research history.

    Returns:
        dict with keys: total, critical, high, medium, low
    """
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM cve_history")
    total = cursor.fetchone()[0]

    stats = {"total": total}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cursor.execute(
            "SELECT COUNT(*) FROM cve_history WHERE severity = ?", (sev,)
        )
        stats[sev.lower()] = cursor.fetchone()[0]

    conn.close()
    return stats


# ── Quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] Initializing database...")
    init_db()
    print("[+] Database ready!")
    print(f"[+] Location: {DB_PATH}")

    # Insert a fake CVE to test
    test_cve = {
        "id":          "CVE-2021-44228",
        "severity":    "CRITICAL",
        "score":       "10.0",
        "description": "Apache Log4j2 RCE vulnerability.",
        "published":   "2021-12-10",
        "references":  [],
    }

    print("\n[*] Saving test CVE...")
    save_cve(test_cve)
    print("[+] Saved!")

    print("\n[*] Fetching history...")
    history = get_history()
    for row in history:
        print(f"  {row['cve_id']} | {row['severity']} | looked up: {row['looked_up']}")

    print("\n[*] Stats:")
    stats = get_stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")