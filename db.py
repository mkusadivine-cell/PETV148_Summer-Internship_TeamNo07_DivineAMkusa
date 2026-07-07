"""
db.py
SQLite persistence layer for LogSentinel.
Handles schema creation and read/write helpers used by app.py.
"""
import sqlite3
import pandas as pd
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path(__file__).parent / "logsentinel.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file     TEXT,
    log_type        TEXT,          -- apache | nginx | syslog
    ip              TEXT,
    timestamp       TEXT,          -- ISO 8601
    method          TEXT,
    url             TEXT,
    protocol        TEXT,
    status          INTEGER,
    size            INTEGER,
    referrer        TEXT,
    user_agent      TEXT,
    event_type      TEXT,          -- request | auth_fail | auth_success | other
    raw_line        TEXT
);

CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_status ON logs(status);

CREATE TABLE IF NOT EXISTS anomalies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    type            TEXT,          -- brute_force | http_flood | error_flood | suspicious_ua | after_hours
    severity        TEXT,          -- low | medium | high | critical
    ip              TEXT,
    window_start    TEXT,
    window_end      TEXT,
    count           INTEGER,
    description     TEXT,
    details         TEXT           -- JSON blob with extra context
);

CREATE INDEX IF NOT EXISTS idx_anom_type ON anomalies(type);
CREATE INDEX IF NOT EXISTS idx_anom_ip ON anomalies(ip);

CREATE TABLE IF NOT EXISTS uploads (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    filename        TEXT,
    log_type        TEXT,
    row_count       INTEGER,
    uploaded_at     TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def insert_logs(df: pd.DataFrame, source_file: str, log_type: str):
    if df.empty:
        return 0
    df = df.copy()
    df["source_file"] = source_file
    df["timestamp"] = df["timestamp"].astype(str)
    cols = ["source_file", "log_type", "ip", "timestamp", "method", "url",
            "protocol", "status", "size", "referrer", "user_agent",
            "event_type", "raw_line"]
    for c in cols:
        if c not in df.columns:
            df[c] = None
    with get_conn() as conn:
        df[cols].to_sql("logs", conn, if_exists="append", index=False)
        conn.execute(
            "INSERT INTO uploads (filename, log_type, row_count) VALUES (?, ?, ?)",
            (source_file, log_type, len(df))
        )
    return len(df)


def clear_anomalies():
    with get_conn() as conn:
        conn.execute("DELETE FROM anomalies")


def clear_all():
    with get_conn() as conn:
        conn.execute("DELETE FROM logs")
        conn.execute("DELETE FROM anomalies")
        conn.execute("DELETE FROM uploads")


def insert_anomalies(df: pd.DataFrame):
    if df.empty:
        return 0
    with get_conn() as conn:
        df.to_sql("anomalies", conn, if_exists="append", index=False)
    return len(df)


def read_logs() -> pd.DataFrame:
    with get_conn() as conn:
        df = pd.read_sql("SELECT * FROM logs", conn)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=False)
    return df


def read_anomalies(type_filter=None, severity_filter=None, limit=500) -> pd.DataFrame:
    query = "SELECT * FROM anomalies WHERE 1=1"
    params = []
    if type_filter:
        query += " AND type = ?"
        params.append(type_filter)
    if severity_filter:
        query += " AND severity = ?"
        params.append(severity_filter)
    query += " ORDER BY window_start DESC LIMIT ?"
    params.append(limit)
    with get_conn() as conn:
        return pd.read_sql(query, conn, params=params)


def get_stats():
    with get_conn() as conn:
        total_logs = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        total_anomalies = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
        unique_ips = conn.execute("SELECT COUNT(DISTINCT ip) FROM logs").fetchone()[0]
        error_count = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE status >= 400"
        ).fetchone()[0]
        uploads = conn.execute(
            "SELECT COUNT(*) FROM uploads"
        ).fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM anomalies WHERE severity = 'critical'"
        ).fetchone()[0]
    return {
        "total_logs": total_logs,
        "total_anomalies": total_anomalies,
        "unique_ips": unique_ips,
        "error_count": error_count,
        "uploads": uploads,
        "critical_anomalies": critical,
    }
