"""
app.py
LogSentinel - Flask web app that ingests Apache/NGINX/syslog logs,
parses them with regex + pandas, stores them in SQLite, detects
anomalies (brute force, 404/error floods, request floods, suspicious
user agents, after-hours access) and serves an interactive Chart.js
dashboard.
"""
import os
import json
import uuid
import pandas as pd
from flask import Flask, request, jsonify, render_template

import db
import parser as logparser
import detector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXT = {".log", ".txt"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB

os.makedirs(UPLOAD_DIR, exist_ok=True)
db.init_db()


def _allowed(filename):
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXT or ext == ""


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

@app.route("/api/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not _allowed(file.filename):
        return jsonify({"error": "Unsupported file type. Use .log or .txt"}), 400

    log_type = request.form.get("log_type", "auto")
    safe_name = f"{uuid.uuid4().hex}_{os.path.basename(file.filename)}"
    save_path = os.path.join(UPLOAD_DIR, safe_name)
    file.save(save_path)

    try:
        df, detected_type, skipped = logparser.parse_file(save_path, log_type)
    except Exception as exc:
        return jsonify({"error": f"Failed to parse file: {exc}"}), 500

    if df.empty:
        return jsonify({
            "error": "No parseable log lines found. Check the log format.",
            "skipped": skipped
        }), 422

    inserted = db.insert_logs(df, file.filename, detected_type)

    return jsonify({
        "message": "File ingested successfully",
        "filename": file.filename,
        "detected_type": detected_type,
        "rows_inserted": inserted,
        "rows_skipped": skipped,
    })


@app.route("/api/load-sample", methods=["POST"])
def load_sample():
    """Convenience endpoint that ingests the bundled demo log files."""
    sample_dir = os.path.join(BASE_DIR, "sample_logs")
    files = [
        ("access.log", "web"),
        ("auth.log", "syslog"),
    ]
    total = 0
    for fname, log_type in files:
        path = os.path.join(sample_dir, fname)
        if not os.path.exists(path):
            continue
        df, detected_type, skipped = logparser.parse_file(path, log_type)
        if not df.empty:
            total += db.insert_logs(df, fname, detected_type)
    if total == 0:
        return jsonify({"error": "Sample log files not found on server"}), 500
    return jsonify({"message": f"Loaded {total} sample log rows", "rows_inserted": total})


@app.route("/api/detect", methods=["POST"])
def run_detection():
    """(Re)run anomaly detection over everything currently in the DB."""
    cfg = request.get_json(silent=True) or {}
    config = {
        "brute_force_threshold": int(cfg.get("brute_force_threshold", 5)),
        "brute_force_window": cfg.get("brute_force_window", "5min"),
        "error_flood_threshold": int(cfg.get("error_flood_threshold", 10)),
        "error_flood_window": cfg.get("error_flood_window", "1min"),
        "http_flood_threshold": int(cfg.get("http_flood_threshold", 100)),
        "http_flood_window": cfg.get("http_flood_window", "1min"),
        "after_hours_start": int(cfg.get("after_hours_start", 8)),
        "after_hours_end": int(cfg.get("after_hours_end", 20)),
    }

    df = db.read_logs()
    if df.empty:
        return jsonify({"error": "No logs ingested yet"}), 400

    anomalies = detector.run_all(df, config)
    db.clear_anomalies()
    inserted = db.insert_anomalies(anomalies)

    return jsonify({
        "message": "Detection complete",
        "anomalies_found": inserted,
        "config": config,
    })


@app.route("/api/reset", methods=["POST"])
def reset():
    db.clear_all()
    return jsonify({"message": "All data cleared"})


# ---------------------------------------------------------------------------
# Dashboard data APIs
# ---------------------------------------------------------------------------

@app.route("/api/summary")
def api_summary():
    return jsonify(db.get_stats())


_FREQ_ALIASES = {"1H": "1h", "H": "h", "1min": "1min", "5min": "5min", "1T": "1min"}


@app.route("/api/timeseries")
def api_timeseries():
    interval = request.args.get("interval", "1h")
    interval = _FREQ_ALIASES.get(interval, interval)
    df = db.read_logs()
    if df.empty:
        return jsonify({"labels": [], "requests": [], "errors": []})

    df = df.set_index("timestamp").sort_index()
    total = df["ip"].resample(interval).count()
    errors = df[df["status"] >= 400]["ip"].resample(interval).count()
    errors = errors.reindex(total.index, fill_value=0)

    return jsonify({
        "labels": [t.isoformat() for t in total.index],
        "requests": total.tolist(),
        "errors": errors.tolist(),
    })


@app.route("/api/status-codes")
def api_status_codes():
    df = db.read_logs()
    if df.empty:
        return jsonify({"labels": [], "counts": []})
    counts = df["status"].dropna().astype(int).value_counts().sort_index()
    return jsonify({
        "labels": [str(s) for s in counts.index],
        "counts": counts.tolist(),
    })


@app.route("/api/top-ips")
def api_top_ips():
    limit = int(request.args.get("limit", 10))
    df = db.read_logs()
    if df.empty:
        return jsonify({"labels": [], "counts": []})
    counts = df["ip"].dropna().value_counts().head(limit)
    return jsonify({
        "labels": counts.index.tolist(),
        "counts": counts.tolist(),
    })


@app.route("/api/anomaly-summary")
def api_anomaly_summary():
    df = db.read_anomalies(limit=100000)
    if df.empty:
        return jsonify({"by_type": {}, "by_severity": {}})
    return jsonify({
        "by_type": df["type"].value_counts().to_dict(),
        "by_severity": df["severity"].value_counts().to_dict(),
    })


@app.route("/api/anomalies")
def api_anomalies():
    type_filter = request.args.get("type") or None
    severity_filter = request.args.get("severity") or None
    limit = int(request.args.get("limit", 200))
    df = db.read_anomalies(type_filter, severity_filter, limit)
    if df.empty:
        return jsonify([])
    return jsonify(df.to_dict(orient="records"))


@app.route("/api/hourly-distribution")
def api_hourly_distribution():
    df = db.read_logs()
    if df.empty:
        return jsonify({"labels": list(range(24)), "counts": [0] * 24})
    hours = df["timestamp"].dt.hour.value_counts().reindex(range(24), fill_value=0)
    return jsonify({
        "labels": [str(h) for h in hours.index],
        "counts": hours.tolist(),
    })


@app.route("/api/suspicious-agents")
def api_suspicious_agents():
    df = db.read_logs()
    if df.empty:
        return jsonify([])
    df = logparser.add_derived_flags(df)
    sub = df[df["is_suspicious_ua"] == True]  # noqa: E712
    if sub.empty:
        return jsonify([])
    grp = sub.groupby("user_agent").agg(
        count=("ip", "count"),
        unique_ips=("ip", "nunique")
    ).reset_index().sort_values("count", ascending=False).head(20)
    return jsonify(grp.to_dict(orient="records"))


@app.route("/api/logs")
def api_logs():
    limit = int(request.args.get("limit", 100))
    df = db.read_logs()
    if df.empty:
        return jsonify([])
    df = df.sort_values("timestamp", ascending=False).head(limit)
    out = df[["timestamp", "ip", "method", "url", "status", "user_agent", "event_type"]].copy()
    out["timestamp"] = out["timestamp"].astype(str)
    return jsonify(out.to_dict(orient="records"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
