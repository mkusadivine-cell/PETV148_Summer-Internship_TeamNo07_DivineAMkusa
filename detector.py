"""
detector.py
Pandas-based anomaly detection over parsed log data:
  - Brute-force login attempts (repeated auth failures / 401-403 bursts per IP)
  - HTTP request floods (possible DoS) per IP
  - 404 / error floods per IP (recon / scanning behaviour)
  - Suspicious user agents (scanners, exploit tools, empty/non-browser UAs)
  - After-hours access (especially to sensitive paths)
"""
import json
import pandas as pd
from parser import add_derived_flags

DEFAULT_CONFIG = {
    "brute_force_threshold": 5,      # failed auths within window
    "brute_force_window": "5min",
    "error_flood_threshold": 10,     # 404s within window
    "error_flood_window": "1min",
    "http_flood_threshold": 100,     # total requests within window
    "http_flood_window": "1min",
    "after_hours_start": 8,          # business hours 08:00-20:00
    "after_hours_end": 20,
}


def _severity_from_ratio(count, threshold):
    ratio = count / max(threshold, 1)
    if ratio >= 4:
        return "critical"
    if ratio >= 2:
        return "high"
    if ratio >= 1.2:
        return "medium"
    return "low"


def _prep(df):
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if hasattr(df["timestamp"].dt, "tz") and df["timestamp"].dt.tz is not None:
        df["timestamp"] = df["timestamp"].dt.tz_localize(None)
    df = df.dropna(subset=["timestamp"])
    df = add_derived_flags(df)
    return df


def detect_brute_force(df, threshold=5, window="5min"):
    df = _prep(df)
    mask = (df["event_type"] == "auth_fail") | (
        (df["event_type"] == "request") &
        (df["status"].isin([401, 403])) &
        (df["is_sensitive_path"])
    )
    sub = df[mask & df["ip"].notna()]
    if sub.empty:
        return pd.DataFrame()

    rows = []
    for ip, grp in sub.groupby("ip"):
        grp = grp.set_index("timestamp").sort_index()
        counts = grp["ip"].resample(window).count()
        flagged = counts[counts >= threshold]
        for win_start, count in flagged.items():
            win_end = win_start + pd.Timedelta(window)
            users = grp.loc[win_start:win_end]
            sample_users = [u for u in users.get("url", pd.Series(dtype=str)).head(3)]
            rows.append({
                "type": "brute_force",
                "severity": _severity_from_ratio(count, threshold),
                "ip": ip,
                "window_start": str(win_start),
                "window_end": str(win_end),
                "count": int(count),
                "description": f"{int(count)} failed authentication attempts from {ip} "
                                f"within {window}",
                "details": json.dumps({"sample_targets": sample_users}),
            })
    return pd.DataFrame(rows)


def detect_error_flood(df, threshold=10, window="1min"):
    df = _prep(df)
    sub = df[(df["event_type"] == "request") & (df["status"] == 404) & df["ip"].notna()]
    if sub.empty:
        return pd.DataFrame()

    rows = []
    for ip, grp in sub.groupby("ip"):
        grp = grp.set_index("timestamp").sort_index()
        counts = grp["ip"].resample(window).count()
        flagged = counts[counts >= threshold]
        for win_start, count in flagged.items():
            win_end = win_start + pd.Timedelta(window)
            urls = grp.loc[win_start:win_end, "url"].dropna().unique()[:5].tolist()
            rows.append({
                "type": "error_flood",
                "severity": _severity_from_ratio(count, threshold),
                "ip": ip,
                "window_start": str(win_start),
                "window_end": str(win_end),
                "count": int(count),
                "description": f"{int(count)} HTTP 404s from {ip} within {window} "
                                f"(possible content/endpoint scanning)",
                "details": json.dumps({"sample_urls": urls}),
            })
    return pd.DataFrame(rows)


def detect_http_flood(df, threshold=100, window="1min"):
    df = _prep(df)
    sub = df[(df["event_type"] == "request") & df["ip"].notna()]
    if sub.empty:
        return pd.DataFrame()

    rows = []
    for ip, grp in sub.groupby("ip"):
        grp = grp.set_index("timestamp").sort_index()
        counts = grp["ip"].resample(window).count()
        flagged = counts[counts >= threshold]
        for win_start, count in flagged.items():
            win_end = win_start + pd.Timedelta(window)
            rows.append({
                "type": "http_flood",
                "severity": _severity_from_ratio(count, threshold),
                "ip": ip,
                "window_start": str(win_start),
                "window_end": str(win_end),
                "count": int(count),
                "description": f"{int(count)} requests from {ip} within {window} "
                                f"(possible flood / DoS behaviour)",
                "details": json.dumps({}),
            })
    return pd.DataFrame(rows)


def detect_suspicious_ua(df):
    df = _prep(df)
    sub = df[(df.get("is_suspicious_ua") == True) & df["ip"].notna()]  # noqa: E712
    if sub.empty:
        return pd.DataFrame()

    rows = []
    grouped = sub.groupby(["ip", "user_agent"])
    for (ip, ua), grp in grouped:
        count = len(grp)
        severity = "high" if count >= 20 else ("medium" if count >= 5 else "low")
        rows.append({
            "type": "suspicious_ua",
            "severity": severity,
            "ip": ip,
            "window_start": str(grp["timestamp"].min()),
            "window_end": str(grp["timestamp"].max()),
            "count": int(count),
            "description": f"Suspicious user agent '{ua or '(empty)'}' seen {count} "
                            f"time(s) from {ip}",
            "details": json.dumps({"user_agent": ua,
                                    "sample_urls": grp["url"].dropna().unique()[:5].tolist()}),
        })
    return pd.DataFrame(rows)


def detect_after_hours(df, start_hour=8, end_hour=20):
    df = _prep(df)
    sub = df[df["event_type"].isin(["request", "auth_fail", "auth_success"])].copy()
    if sub.empty:
        return pd.DataFrame()

    sub["hour"] = sub["timestamp"].dt.hour
    outside = sub[(sub["hour"] < start_hour) | (sub["hour"] >= end_hour)]
    if outside.empty:
        return pd.DataFrame()

    outside = outside.copy()
    outside["date"] = outside["timestamp"].dt.date

    rows = []
    for (ip, date), grp in outside.groupby(["ip", "date"]):
        if not ip:
            continue
        count = len(grp)
        touches_sensitive = bool(grp.get("is_sensitive_path", pd.Series(dtype=bool)).any())
        has_auth_fail = bool((grp["event_type"] == "auth_fail").any())
        if touches_sensitive or has_auth_fail:
            severity = "high"
        elif count >= 10:
            severity = "medium"
        else:
            severity = "low"
        rows.append({
            "type": "after_hours",
            "severity": severity,
            "ip": ip,
            "window_start": str(grp["timestamp"].min()),
            "window_end": str(grp["timestamp"].max()),
            "count": int(count),
            "description": f"{count} access event(s) from {ip} outside business hours "
                            f"({start_hour}:00-{end_hour}:00) on {date}",
            "details": json.dumps({
                "touches_sensitive_path": touches_sensitive,
                "sample_urls": grp["url"].dropna().unique()[:5].tolist()
            }),
        })
    return pd.DataFrame(rows)


def run_all(df, config=None):
    """Run every detector and return one concatenated anomalies DataFrame."""
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    frames = [
        detect_brute_force(df, cfg["brute_force_threshold"], cfg["brute_force_window"]),
        detect_error_flood(df, cfg["error_flood_threshold"], cfg["error_flood_window"]),
        detect_http_flood(df, cfg["http_flood_threshold"], cfg["http_flood_window"]),
        detect_suspicious_ua(df),
        detect_after_hours(df, cfg["after_hours_start"], cfg["after_hours_end"]),
    ]
    frames = [f for f in frames if not f.empty]
    if not frames:
        return pd.DataFrame(columns=[
            "type", "severity", "ip", "window_start", "window_end",
            "count", "description", "details"
        ])
    result = pd.concat(frames, ignore_index=True)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    result["_sev_rank"] = result["severity"].map(sev_order)
    result = result.sort_values(["_sev_rank", "window_start"]).drop(columns="_sev_rank")
    return result
