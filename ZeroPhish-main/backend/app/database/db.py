"""
PhishGuard AI — Database Module
SQLite database using Python's built-in sqlite3 module.
Automatically creates database and tables on startup.
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from backend.app.config import DATABASE_PATH


def get_connection() -> sqlite3.Connection:
    """Get a database connection with row factory."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    """Create database file and tables if they don't exist."""
    # Ensure directory exists
    db_dir = os.path.dirname(DATABASE_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                input_type TEXT NOT NULL,
                input_text TEXT NOT NULL,
                classification TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                ml_probability REAL NOT NULL,
                indicators TEXT NOT NULL,
                recommendations TEXT NOT NULL,
                explanation TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()
        print(f"[DB] Database initialized at {DATABASE_PATH}")
    except Exception as e:
        print(f"[DB] ERROR: Failed to initialize database: {e}")
        raise


def save_scan(
    input_type: str,
    input_text: str,
    classification: str,
    risk_score: int,
    ml_probability: float,
    indicators: list[str],
    recommendations: list[str],
    explanation: str = "",
) -> int:
    """Save a scan result and return the scan ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (input_type, input_text, classification, risk_score,
                          ml_probability, indicators, recommendations, explanation, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        input_type,
        input_text[:2000],  # Truncate very long inputs
        classification,
        risk_score,
        ml_probability,
        json.dumps(indicators),
        json.dumps(recommendations),
        explanation,
        datetime.now(timezone.utc).isoformat(),
    ))
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def get_history(limit: int = 50) -> list[dict]:
    """Get scan history, most recent first."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, input_type, input_text, classification, risk_score,
               ml_probability, indicators, recommendations, explanation, timestamp
        FROM scans ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()

    result = []
    for row in rows:
        result.append({
            "id": row["id"],
            "input_type": row["input_type"],
            "input_text": row["input_text"][:200],  # Truncate for display
            "classification": row["classification"],
            "risk_score": row["risk_score"],
            "ml_probability": row["ml_probability"],
            "indicators": json.loads(row["indicators"]),
            "recommendations": json.loads(row["recommendations"]),
            "explanation": row["explanation"],
            "timestamp": row["timestamp"],
        })
    return result


def get_statistics() -> dict:
    """Get scan statistics from the database."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM scans")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE classification = 'PHISHING'")
    phishing = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE classification = 'SUSPICIOUS'")
    suspicious = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE classification = 'SAFE'")
    safe = cursor.fetchone()["count"]

    cursor.execute("SELECT AVG(risk_score) as avg_score FROM scans")
    avg_row = cursor.fetchone()
    avg_score = round(avg_row["avg_score"], 1) if avg_row["avg_score"] else 0

    # Recent scans for chart
    cursor.execute("""
        SELECT classification, risk_score, timestamp
        FROM scans ORDER BY id DESC LIMIT 20
    """)
    recent = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "total_scans": total,
        "phishing_count": phishing,
        "suspicious_count": suspicious,
        "safe_count": safe,
        "average_risk_score": avg_score,
        "recent_scans": recent,
    }
