"""
parser.py
Regex-based parsing of Apache/NGINX access logs and syslog-style
auth logs into a tidy pandas DataFrame ready for SQLite storage
and anomaly detection.
"""
import re
import pandas as pd
from datetime import datetime
from dateutil import parser as dtparser

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Apache/NGINX "combined" log format, e.g.:
# 127.0.0.1 - frank [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://ref" "Mozilla/5.0"
COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>[\da-fA-F:.]+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# Common Log Format fallback (no referrer/user-agent fields)
COMMON_LOG_RE = re.compile(
    r'^(?P<ip>[\da-fA-F:.]+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

# Syslog header, e.g.:
# Jul  6 09:14:22 webhost sshd[1417]: Failed password for invalid user admin from 203.0.113.7 port 51514 ssh2
SYSLOG_RE = re.compile(
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+'
    r'(?P<process>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
)

SSH_FAILED_RE = re.compile(
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F:.]+) port (?P<port>\d+)'
)
SSH_INVALID_USER_RE = re.compile(
    r'Invalid user (?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)'
)
SSH_ACCEPTED_RE = re.compile(
    r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\da-fA-F:.]+) port (?P<port>\d+)'
)

# Known scanner / attack-tool / non-browser user agents (case-insensitive)
SUSPICIOUS_UA_PATTERNS = [
    r'sqlmap', r'nikto', r'nmap', r'masscan', r'zgrab', r'gobuster',
    r'dirbuster', r'wpscan', r'acunetix', r'nessus', r'openvas', r'metasploit',
    r'hydra', r'nuclei', r'fuzzer', r'python-requests', r'python-urllib',
    r'curl/', r'wget/', r'go-http-client', r'libwww-perl', r'scrapy',
    r'^\-$', r'^$', r'bot(?!.*(?:googlebot|bingbot|duckduckbot))',
]
SUSPICIOUS_UA_RE = re.compile('|'.join(SUSPICIOUS_UA_PATTERNS), re.IGNORECASE)

SENSITIVE_PATH_RE = re.compile(
    r'(admin|wp-login|wp-admin|phpmyadmin|login|config|\.env|\.git|backup|shell|cmd\.php|xmlrpc)',
    re.IGNORECASE
)


def _parse_apache_ts(ts_str):
    # 10/Oct/2023:13:55:36 -0700
    try:
        return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        try:
            return dtparser.parse(ts_str)
        except Exception:
            return pd.NaT


def _parse_syslog_ts(month, day, time_str, year=None):
    year = year or datetime.now().year
    try:
        return dtparser.parse(f"{month} {day} {year} {time_str}")
    except Exception:
        return pd.NaT


def _clean_size(val):
    if val is None or val == '-':
        return 0
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0


def add_derived_flags(df):
    """Ensure is_suspicious_ua / is_sensitive_path columns exist, computing
    them from user_agent/url if the dataframe came from SQLite (which only
    stores raw columns) rather than fresh parsing."""
    if "is_suspicious_ua" not in df.columns:
        df["is_suspicious_ua"] = df["user_agent"].fillna("").apply(
            lambda ua: bool(SUSPICIOUS_UA_RE.search(ua)) if ua else False
        )
    if "is_sensitive_path" not in df.columns:
        df["is_sensitive_path"] = df["url"].fillna("").apply(
            lambda u: bool(SENSITIVE_PATH_RE.search(u))
        )
    return df


def detect_log_type(sample_lines):
    """Guess whether the file is apache/nginx combined logs or syslog."""
    for line in sample_lines:
        line = line.strip()
        if not line:
            continue
        if COMBINED_LOG_RE.match(line) or COMMON_LOG_RE.match(line):
            return "web"
        if SYSLOG_RE.match(line):
            return "syslog"
    return "unknown"


def parse_web_line(line):
    m = COMBINED_LOG_RE.match(line) or COMMON_LOG_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    status = int(g["status"])
    ua = g.get("user_agent") or ""
    row = {
        "ip": g["ip"],
        "timestamp": _parse_apache_ts(g["timestamp"]),
        "method": g["method"],
        "url": g["url"],
        "protocol": g["protocol"],
        "status": status,
        "size": _clean_size(g.get("size")),
        "referrer": g.get("referrer") or "",
        "user_agent": ua,
        "event_type": "request",
        "raw_line": line,
    }
    return row


def parse_syslog_line(line, default_year=None):
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    ts = _parse_syslog_ts(g["month"], g["day"], g["time"], default_year)
    message = g["message"]

    event_type = "other"
    ip = None
    status = None

    fail_m = SSH_FAILED_RE.search(message)
    invalid_m = SSH_INVALID_USER_RE.search(message)
    accepted_m = SSH_ACCEPTED_RE.search(message)

    if fail_m:
        event_type = "auth_fail"
        ip = fail_m.group("ip")
        status = 401
    elif invalid_m:
        event_type = "auth_fail"
        ip = invalid_m.group("ip")
        status = 401
    elif accepted_m:
        event_type = "auth_success"
        ip = accepted_m.group("ip")
        status = 200

    row = {
        "ip": ip,
        "timestamp": ts,
        "method": g["process"],
        "url": message[:200],
        "protocol": "syslog",
        "status": status,
        "size": 0,
        "referrer": "",
        "user_agent": "",
        "event_type": event_type,
        "raw_line": line,
    }
    return row


def parse_file(path, log_type="auto"):
    """
    Parse a log file into a pandas DataFrame.
    log_type: 'auto' | 'web' | 'syslog'
    Returns (dataframe, detected_type, n_skipped)
    """
    with open(path, "r", errors="ignore") as f:
        lines = f.readlines()

    if log_type == "auto":
        log_type = detect_log_type(lines[:50])

    rows = []
    skipped = 0
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        row = None
        if log_type == "web":
            row = parse_web_line(line)
        elif log_type == "syslog":
            row = parse_syslog_line(line)
        else:
            row = parse_web_line(line) or parse_syslog_line(line)

        if row is None:
            skipped += 1
            continue
        rows.append(row)

    df = pd.DataFrame(rows)
    if df.empty:
        return df, log_type, skipped

    df["log_type"] = log_type
    df = df.dropna(subset=["timestamp"])
    df = add_derived_flags(df)
    return df, log_type, skipped
