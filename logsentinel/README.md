# LogSentinel

A Flask web app that ingests Apache / NGINX / syslog logs, parses them
with regex + pandas, stores them in SQLite, detects anomalies, and
visualizes findings on an interactive Chart.js dashboard.

## Detected anomalies

| Type | Logic |
|---|---|
| **Brute force** | `auth_fail` events (SSH `Failed password`, etc.) or repeated 401/403 hits on sensitive paths (`/login`, `/admin`, ...) from one IP, above a threshold within a rolling time window (default: 5 in 5 minutes). |
| **404 flood** | Many HTTP 404s from one IP in a short window (default: 10 in 1 minute) — typical of directory/content scanning. |
| **Request flood** | High overall request volume from one IP in a short window (default: 100 in 1 minute) — possible DoS. |
| **Suspicious user agent** | Requests whose User-Agent matches known scanner/exploit tools (sqlmap, nikto, nmap, wpscan, etc.), scripting clients (curl, python-requests), or is empty. |
| **After-hours access** | Requests/logins outside configured business hours, with higher severity if they touch a sensitive path or are failed logins. |

## Supported log formats

- **Apache / NGINX combined log format**
  `127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "referrer" "user-agent"`
- **Common Log Format** (no referrer/UA fields)
- **Syslog auth log** (e.g. `/var/log/auth.log`), specifically SSH
  `Failed password` / `Invalid user` / `Accepted publickey` lines

The parser auto-detects the format, or you can force it via the format
dropdown on upload.

## Running locally

```bash
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000

Click **"Load sample data"** on the dashboard to try it instantly with
the bundled synthetic logs in `sample_logs/` (they contain one example
of every anomaly type).

## Project layout

```
app.py            Flask routes: ingestion, detection, dashboard JSON APIs
parser.py         Regex parsing of Apache/NGINX/syslog lines -> pandas DataFrame
detector.py        Pandas-based anomaly detectors (windowed groupby/resample)
db.py             SQLite schema + read/write helpers
templates/index.html   Dashboard shell
static/css/style.css   Dashboard styling
static/js/dashboard.js Chart.js wiring + API calls
sample_logs/      Synthetic demo logs + generator script
```

## API reference

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/upload` | POST (multipart `file`, `log_type`) | Parse & ingest a log file |
| `/api/load-sample` | POST | Ingest bundled demo logs |
| `/api/detect` | POST (JSON thresholds) | (Re)run all detectors over ingested logs |
| `/api/reset` | POST | Wipe all logs & anomalies |
| `/api/summary` | GET | KPI counts |
| `/api/timeseries?interval=5min` | GET | Requests/errors over time |
| `/api/status-codes` | GET | HTTP status code histogram |
| `/api/top-ips?limit=10` | GET | Busiest source IPs |
| `/api/anomaly-summary` | GET | Anomaly counts by type/severity |
| `/api/anomalies?type=&severity=` | GET | Anomaly records |
| `/api/hourly-distribution` | GET | Requests by hour of day (0-23) |
| `/api/suspicious-agents` | GET | Suspicious user agents seen |
| `/api/logs?limit=100` | GET | Most recent raw parsed log rows |

## Notes / limitations

- Syslog lines have no year in the timestamp; the current year is
  assumed. Point-in-time accuracy across a year boundary isn't handled.
- Detection re-runs over the *entire* logs table each time (not
  incremental) — fine for demo/analysis-sized datasets; for very large
  volumes you'd want to shard by time range or persist per-file
  detection state.
- This ships with Flask's dev server. Put it behind gunicorn/uwsgi +
  nginx for anything beyond local use.
