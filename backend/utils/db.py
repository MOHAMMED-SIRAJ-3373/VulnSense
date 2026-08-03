"""
VulnSense — SQLite Database Layer
===================================
All database logic lives here. Flask routes call these functions
instead of writing SQL directly — keeps routes thin and testable.
"""

import sqlite3, os, json, secrets
from datetime import datetime, timedelta

ROOT    = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
DB_PATH = os.path.join(ROOT, "data", "vulnsense.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row          # rows behave like dicts
    conn.execute("PRAGMA journal_mode=WAL") # safer concurrent writes
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables on first run. Safe to call repeatedly."""
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'analyst',
            created_at    TEXT NOT NULL,
            last_login    TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            username   TEXT NOT NULL,
            role       TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS scans (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      TEXT UNIQUE NOT NULL,
            host         TEXT NOT NULL,
            started_at   TEXT NOT NULL,
            completed_at TEXT,
            method       TEXT,
            total_open   INTEGER DEFAULT 0,
            status       TEXT DEFAULT 'running',
            initiated_by TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id       TEXT NOT NULL,
            finding_id    TEXT UNIQUE,
            host          TEXT,
            port          INTEGER,
            protocol      TEXT,
            service       TEXT,
            vuln_type     TEXT,
            banner        TEXT,
            detail        TEXT,
            risk_label    TEXT,
            confidence    REAL,
            uncertain     INTEGER DEFAULT 0,
            explanation   TEXT,
            probabilities TEXT,
            contributions TEXT,
            cves          TEXT,
            raw_features  TEXT,
            remediation_status TEXT DEFAULT 'open',
            remediation_note   TEXT,
            created_at    TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        );
    """)
    conn.commit()
    conn.close()


# ── Users ─────────────────────────────────────────────────────

def get_user_by_username(username):
    conn = get_conn()
    row  = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(username, password_hash, role="analyst"):
    conn = get_conn()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
        (username, password_hash, role, datetime.utcnow().isoformat())
    )
    conn.commit()
    uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return uid


def update_last_login(user_id):
    conn = get_conn()
    conn.execute("UPDATE users SET last_login=? WHERE id=?",
                 (datetime.utcnow().isoformat(), user_id))
    conn.commit(); conn.close()


# ── Sessions ──────────────────────────────────────────────────

SESSION_HOURS = 8


def create_session(user_id, username, role):
    token = secrets.token_hex(32)   # cryptographically secure random token
    now   = datetime.utcnow()
    exp   = now + timedelta(hours=SESSION_HOURS)
    conn  = get_conn()
    conn.execute(
        "INSERT INTO sessions (token,user_id,username,role,created_at,expires_at) VALUES (?,?,?,?,?,?)",
        (token, user_id, username, role, now.isoformat(), exp.isoformat())
    )
    conn.commit(); conn.close()
    return token


def get_session(token):
    conn = get_conn()
    row  = conn.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
    conn.close()
    if not row:
        return None
    sess = dict(row)
    # Check expiry on every request — expired sessions are rejected
    if datetime.utcnow() > datetime.fromisoformat(sess["expires_at"]):
        delete_session(token)
        return None
    return sess


def delete_session(token):
    conn = get_conn()
    conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit(); conn.close()


# ── Scans ─────────────────────────────────────────────────────

def create_scan(scan_id, host, started_at, method, initiated_by):
    conn = get_conn()
    conn.execute(
        "INSERT OR IGNORE INTO scans (scan_id,host,started_at,method,status,initiated_by) VALUES (?,?,?,?,?,?)",
        (scan_id, host, started_at, method, "running", initiated_by)
    )
    conn.commit(); conn.close()


def complete_scan(scan_id, total_open):
    conn = get_conn()
    conn.execute(
        "UPDATE scans SET status=?, completed_at=?, total_open=? WHERE scan_id=?",
        ("complete", datetime.utcnow().isoformat(), total_open, scan_id)
    )
    conn.commit(); conn.close()


def get_all_scans():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT 50").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Findings ──────────────────────────────────────────────────

def save_finding(scan_id, finding, ml_result):
    conn = get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO findings
        (scan_id, finding_id, host, port, protocol, service, vuln_type,
         banner, detail, risk_label, confidence, uncertain, explanation,
         probabilities, contributions, cves, raw_features, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        scan_id,
        finding.get("finding_id"),
        finding.get("host"),
        finding.get("port"),
        finding.get("protocol"),
        finding.get("service"),
        finding.get("vuln_type"),
        finding.get("banner", ""),
        finding.get("detail", ""),
        ml_result.get("label"),
        ml_result.get("confidence"),
        1 if ml_result.get("uncertain") else 0,
        ml_result.get("explanation"),
        json.dumps(ml_result.get("probabilities", {})),
        json.dumps(ml_result.get("contributions", [])),
        json.dumps(finding.get("cves", [])),
        json.dumps({k: finding[k] for k in finding
                    if k not in ("finding_id","host","port","protocol",
                                 "service","vuln_type","banner","detail","cves")}),
        datetime.utcnow().isoformat(),
    ))
    conn.commit(); conn.close()


def get_scan_findings(scan_id):
    conn  = get_conn()
    rows  = conn.execute(
        "SELECT * FROM findings WHERE scan_id=? ORDER BY risk_label, port", (scan_id,)
    ).fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        # Parse JSON fields back into Python objects
        for field in ("probabilities", "contributions", "cves", "raw_features"):
            try:
                d[field] = json.loads(d.get(field) or "[]" if field != "probabilities" else "{}")
            except Exception:
                d[field] = {} if field == "probabilities" else []
        results.append(d)
    return results


def update_remediation(finding_id, status, note=""):
    """Allow analysts to mark a finding as open/in_progress/fixed/accepted."""
    conn = get_conn()
    conn.execute(
        "UPDATE findings SET remediation_status=?, remediation_note=? WHERE finding_id=?",
        (status, note, finding_id)
    )
    conn.commit(); conn.close()


# ── Dashboard stats ───────────────────────────────────────────

def get_dashboard_stats():
    conn = get_conn()
    total_scans    = conn.execute("SELECT COUNT(*) FROM scans WHERE status='complete'").fetchone()[0]
    total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    high   = conn.execute("SELECT COUNT(*) FROM findings WHERE risk_label='High'").fetchone()[0]
    medium = conn.execute("SELECT COUNT(*) FROM findings WHERE risk_label='Medium'").fetchone()[0]
    low    = conn.execute("SELECT COUNT(*) FROM findings WHERE risk_label='Low'").fetchone()[0]

    # Remediation breakdown — useful for the tracker widget
    rem = conn.execute("""
        SELECT remediation_status, COUNT(*) as cnt
        FROM findings GROUP BY remediation_status
    """).fetchall()
    remediation = {r["remediation_status"]: r["cnt"] for r in rem}

    # Recent findings grouped by host for the bar chart
    recent = conn.execute("""
        SELECT host, risk_label, COUNT(*) as cnt
        FROM findings GROUP BY host, risk_label
        ORDER BY cnt DESC LIMIT 12
    """).fetchall()

    # Timeline: findings count per scan (for the trend chart)
    timeline = conn.execute("""
        SELECT s.started_at, s.scan_id,
               SUM(CASE WHEN f.risk_label='High'   THEN 1 ELSE 0 END) as high,
               SUM(CASE WHEN f.risk_label='Medium' THEN 1 ELSE 0 END) as medium,
               SUM(CASE WHEN f.risk_label='Low'    THEN 1 ELSE 0 END) as low
        FROM scans s
        LEFT JOIN findings f ON s.scan_id = f.scan_id
        WHERE s.status='complete'
        GROUP BY s.scan_id
        ORDER BY s.started_at ASC
        LIMIT 20
    """).fetchall()

    conn.close()
    return {
        "total_scans":    total_scans,
        "total_findings": total_findings,
        "high":           high,
        "medium":         medium,
        "low":            low,
        "remediation":    remediation,
        "recent_by_host": [dict(r) for r in recent],
        "timeline":       [dict(r) for r in timeline],
    }


def get_host_score(host):
    """
    Calculate a simple 0-100 security score for a host.
    High findings subtract more than Medium or Low.
    A clean host scores 100.
    """
    conn = get_conn()
    row  = conn.execute("""
        SELECT
            SUM(CASE WHEN risk_label='High'   THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN risk_label='Medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN risk_label='Low'    THEN 1 ELSE 0 END) as low
        FROM findings WHERE host=?
    """, (host,)).fetchone()
    conn.close()
    if not row:
        return 100
    # Penalty weights: High=15pts, Medium=7pts, Low=2pts
    penalty = (row["high"] or 0)*15 + (row["medium"] or 0)*7 + (row["low"] or 0)*2
    return max(0, 100 - penalty)
