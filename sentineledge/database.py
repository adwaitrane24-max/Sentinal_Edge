"""
database.py — SQLite storage for alerts, blocks, and whitelist.
"""
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = "sentineledge.db"
_lock = threading.Lock()


@contextmanager
def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        with c:
            yield c
    finally:
        c.close()


def init_db():
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            alert_id  TEXT    NOT NULL,
            category  TEXT    NOT NULL,
            src_ip    TEXT    NOT NULL,
            detail    TEXT,
            severity  TEXT    NOT NULL,
            action    TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS blocks (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip    TEXT    NOT NULL UNIQUE,
            reason    TEXT,
            blocked_at TEXT   NOT NULL,
            expires_at TEXT
        );
        CREATE TABLE IF NOT EXISTS whitelist (
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            ip     TEXT    NOT NULL UNIQUE,
            note   TEXT
        );
        """)


# ── Alerts ──────────────────────────────────────────────────────────────────

def insert_alert(alert_id, category, src_ip, detail, severity, action):
    with _lock, _conn() as c:
        c.execute(
            "INSERT INTO alerts (timestamp,alert_id,category,src_ip,detail,severity,action) "
            "VALUES (?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), alert_id, category, src_ip, detail, severity, action),
        )


def get_alerts(limit=100):
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]

def get_alert_summary():
    with _conn() as c:
        row = c.execute("SELECT COUNT(*) AS total_alerts, COALESCE(MAX(id),0) AS last_alert_id, COALESCE(SUM(severity='high'),0) AS high_severity FROM alerts").fetchone()
    return dict(row)


# ── Blocks ───────────────────────────────────────────────────────────────────

def add_block(src_ip, reason, expires_at=None):
    with _lock, _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO blocks (src_ip,reason,blocked_at,expires_at) VALUES (?,?,?,?)",
            (src_ip, reason, datetime.now(timezone.utc).isoformat(), expires_at),
        )


def remove_block(src_ip):
    with _lock, _conn() as c:
        c.execute("DELETE FROM blocks WHERE src_ip=?", (src_ip,))


def get_blocks():
    with _conn() as c:
        rows = c.execute("SELECT * FROM blocks ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def is_blocked(src_ip):
    with _conn() as c:
        row = c.execute("SELECT 1 FROM blocks WHERE src_ip=?", (src_ip,)).fetchone()
    return row is not None


# ── Whitelist ────────────────────────────────────────────────────────────────

def add_whitelist(ip, note=""):
    with _lock, _conn() as c:
        c.execute("INSERT OR IGNORE INTO whitelist (ip,note) VALUES (?,?)", (ip, note))


def remove_whitelist(ip):
    with _lock, _conn() as c:
        c.execute("DELETE FROM whitelist WHERE ip=?", (ip,))


def get_whitelist():
    with _conn() as c:
        rows = c.execute("SELECT * FROM whitelist").fetchall()
    return [dict(r) for r in rows]


def is_whitelisted(ip):
    with _conn() as c:
        row = c.execute("SELECT 1 FROM whitelist WHERE ip=?", (ip,)).fetchone()
    return row is not None
