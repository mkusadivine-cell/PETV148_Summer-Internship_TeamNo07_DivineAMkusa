"""Generate synthetic access.log and auth.log sample files covering
every anomaly type LogSentinel detects, for demo/testing purposes."""
import random
from datetime import datetime, timedelta

random.seed(42)
BASE = datetime(2026, 7, 1, 0, 0, 0)

NORMAL_IPS = [f"203.0.113.{i}" for i in range(1, 20)]
BRUTE_IP = "198.51.100.23"
FLOOD_IP = "198.51.100.77"
SCAN_IP = "198.51.100.55"
UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/126.0",
]
BAD_UA_LIST = [
    "sqlmap/1.7.2#stable (http://sqlmap.org)",
    "() { :; }; curl/7.68.0",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "python-requests/2.31.0",
    "-",
]
PATHS = ["/", "/index.html", "/about", "/products", "/contact", "/blog/post-1", "/images/logo.png"]
SENSITIVE_PATHS = ["/admin", "/wp-login.php", "/phpmyadmin", "/login", "/.env", "/wp-admin"]

lines = []


def apache_ts(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def access_line(ip, dt, method, url, status, size, ua, referrer="-"):
    return f'{ip} - - [{apache_ts(dt)}] "{method} {url} HTTP/1.1" {status} {size} "{referrer}" "{ua}"'


# 1. Normal daytime traffic (business hours 8-20)
t = BASE
for _ in range(600):
    t += timedelta(seconds=random.randint(5, 40))
    hour = 8 + (t.minute % 12)
    dt = t.replace(hour=hour)
    ip = random.choice(NORMAL_IPS)
    ua = random.choice(UA_LIST)
    path = random.choice(PATHS)
    status = random.choices([200, 200, 200, 304, 404], weights=[70, 10, 10, 5, 5])[0]
    lines.append(access_line(ip, dt, "GET", path, status, random.randint(200, 8000), ua))

# 2. After-hours access to sensitive admin path
for i in range(6):
    dt = BASE.replace(hour=2, minute=10 + i * 3)
    lines.append(access_line("203.0.113.99", dt, "GET", "/admin", 401, 512, UA_LIST[0]))

# 3. 404 flood / directory scanning from SCAN_IP within a 1-minute window
scan_start = BASE.replace(hour=14, minute=5, second=0)
for i in range(25):
    dt = scan_start + timedelta(seconds=i * 2)
    path = f"/old/page{i}.php"
    lines.append(access_line(SCAN_IP, dt, "GET", path, 404, 210, BAD_UA_LIST[2]))

# 4. HTTP flood (possible DoS) from FLOOD_IP
flood_start = BASE.replace(hour=16, minute=30, second=0)
for i in range(150):
    dt = flood_start + timedelta(milliseconds=i * 300)
    lines.append(access_line(FLOOD_IP, dt, "GET", "/", 200, 512, BAD_UA_LIST[3]))

# 5. Suspicious user agents scattered through the day
for i in range(10):
    dt = BASE.replace(hour=11, minute=i * 2)
    lines.append(access_line(f"198.51.100.{100+i}", dt, "GET",
                              random.choice(SENSITIVE_PATHS), 403, 300,
                              random.choice(BAD_UA_LIST)))

# 6. Repeated login POST failures (web-based brute force) targeting /login
bf_start = BASE.replace(hour=9, minute=0, second=0)
for i in range(12):
    dt = bf_start + timedelta(seconds=i * 15)
    lines.append(access_line(BRUTE_IP, dt, "POST", "/login", 401, 128, UA_LIST[1]))

random.shuffle(lines)
# re-sort by embedded timestamp so file looks realistic
lines.sort(key=lambda l: l.split("[")[1].split("]")[0])

with open("access.log", "w") as f:
    f.write("\n".join(lines) + "\n")

# ---------------------------------------------------------------------------
# Syslog auth.log with SSH brute force
# ---------------------------------------------------------------------------
auth_lines = []


def syslog_ts(dt):
    return dt.strftime("%b %e %H:%M:%S").replace("  ", " ")


ssh_start = BASE.replace(hour=3, minute=0, second=0)
users = ["root", "admin", "test", "oracle", "ubuntu", "postgres", "git", "deploy"]
for i in range(20):
    dt = ssh_start + timedelta(seconds=i * 10)
    user = random.choice(users)
    auth_lines.append(
        f"{syslog_ts(dt)} webhost sshd[{1000+i}]: Failed password for invalid user "
        f"{user} from 192.0.2.88 port {40000+i} ssh2"
    )

# a couple of normal successful logins during business hours
for i in range(3):
    dt = BASE.replace(hour=9, minute=15 + i)
    auth_lines.append(
        f"{syslog_ts(dt)} webhost sshd[{2000+i}]: Accepted publickey for deploy "
        f"from 203.0.113.5 port {50000+i} ssh2"
    )

with open("auth.log", "w") as f:
    f.write("\n".join(auth_lines) + "\n")

print(f"Wrote {len(lines)} access.log lines and {len(auth_lines)} auth.log lines")
