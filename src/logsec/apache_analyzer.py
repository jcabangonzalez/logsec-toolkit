import re
import os
import json
import time
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from collections import Counter
from datetime import datetime, timedelta
from dotenv import load_dotenv
from anthropic import Anthropic
from google import genai
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

load_dotenv()

log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

FLOOD_THRESHOLD = 10
_MAX_RAW_SCORE = 30
_RECENT_REQUESTS_MAX = 20
SEEN_IPS_FILE = os.path.join(os.path.dirname(__file__), "seen_ips.json")
RISK_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Per-IP request sequences capture order and context (method, URL, status, time).
# Isolated signals (e.g. one 404 or one login POST) are noisy; ordered sequences
# support behavioral correlation—recon then exploit, scan bursts, auth-then-admin—
# which improves detection quality when attack-chain rules are added later.skybyassaultT

WHITELIST = {
    "127.0.0.1",
    "::1",
    "127.",
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
}


def is_whitelisted(ip: str) -> bool:
    if ip in WHITELIST:
        return True
    return any(ip.startswith(prefix) for prefix in WHITELIST if prefix.endswith("."))

SUSPICIOUS_AGENTS = {
    "sqlmap": 4,
    "nikto": 3,
    "masscan": 3,
    "nmap": 2,
    "curl": 1,
    "wget": 1,
}

SCANNER_PATHS = {
    "/.env": 3,
    "/backup.zip": 3,
    "/.git": 2,
    "/xmlrpc.php": 2,
    "/wp-admin": 2,
    "/phpmyadmin": 2,
    "/config.php": 1,
    "/actuator": 1,
    "/console": 1,
}

SQL_PATTERNS = {
    "union select": 3,
    "union%20select": 3,
    "or 1=1": 3,
    "or%201=1": 3,
    "' or '": 2,
    "%27%20or%20": 2,
    "drop table": 3,
    "information_schema": 2,
    "sleep(": 2,
    "benchmark(": 2,
    ";--": 2,
    "';--": 2,
    "concat(": 1,
    "char(": 1,
    "@@version": 2,
    "waitfor delay": 2,
}

def parse_line(line: str):
    match = log_pattern.match(line)
    if not match:
        return None
    data = match.groupdict()
    data["status"] = int(data["status"])
    data["size"] = 0 if data["size"] == "-" else int(data["size"])
    return data


def _record_ip_request(ip_profiles: dict, parsed: dict) -> None:
    """Append one lightweight event; cap history so profiles stay bounded in memory."""
    ip = parsed["ip"]
    if ip not in ip_profiles:
        ip_profiles[ip] = {"requests": 0, "recent_requests": [], "unique_paths": set(), "timestamps": []}
    profile = ip_profiles[ip]
    profile["requests"] += 1
    profile["unique_paths"].add(parsed["url"])
    profile["timestamps"].append(parsed["datetime"])
    profile["recent_requests"].append(
        {
            "method": parsed["method"],
            "url": parsed["url"],
            "status": parsed["status"],
            "timestamp": parsed["datetime"],
        }
    )
    if len(profile["recent_requests"]) > _RECENT_REQUESTS_MAX:
        profile["recent_requests"].pop(0)


def classify_risk(ip: str, ip_count: int, login_attempts: int, scanner_hits: int, flood_count: int, night_count: int = 0, errors_4xx: int = 0, agent_score: int = 0, rate: float = 0.0, sql_hits: int = 0, path_diversity: int = 0, burst_count: int = 0) -> dict:
    if is_whitelisted(ip):
        return {"ip": ip, "risk_level": "LOW", "score": 0, "reasons": []}

    score = 0
    reasons = []
    
    if ip in blocklist:
        score += 10
        reasons.append(f"IP found in threat intelligence blocklist: {ip}")

    if rate >= 100:
        score += 4
        reasons.append(f"Flood rate: {rate:.1f} req/min")
    elif rate >= 20:
        score += 2
        reasons.append(f"High request rate: {rate:.1f} req/min")
    elif rate >= 5:
        score += 1
        reasons.append(f"Elevated rate: {rate:.1f} req/min")

    if login_attempts >= 10:
        score += 4
        reasons.append(f"Likely brute force: {login_attempts} attempts")
    elif login_attempts >= 3:
        score += 2
        reasons.append(f"Multiple login attempts: {login_attempts}")

    if scanner_hits >= 3:
        score += 3
        reasons.append(f"Vulnerability scanner: {scanner_hits} sensitive paths")
    elif scanner_hits >= 1:
        score += 1
        reasons.append(f"Suspicious path access: {scanner_hits}")

    if sql_hits >= 3:
        score += 6
        reasons.append(f"SQL injection: {sql_hits} suspicious query patterns")
    elif sql_hits >= 1:
        score += 4
        reasons.append(f"Possible SQL injection: {sql_hits} patterns in URL")

    if login_attempts >= 3 and scanner_hits >= 1:
        score += 3
        reasons.append(f"Combined brute force + scanning — likely automated attack")

    if errors_4xx >= 50:
        score += 2
        reasons.append(f"High 4xx error count: {errors_4xx}")
    elif errors_4xx >= 20:
        score += 1
        reasons.append(f"Elevated 4xx errors: {errors_4xx}")

    if agent_score >= 8:
        score += 6
        reasons.append(f"Suspicious User-Agent (score: {agent_score})")
    elif agent_score >= 4:
        score += 4
        reasons.append(f"Suspicious User-Agent (score: {agent_score})")
    elif agent_score >= 2:
        score += 2
        reasons.append(f"Suspicious User-Agent (score: {agent_score})")
    elif agent_score >= 1:
        score += 1
        reasons.append(f"Suspicious User-Agent (score: {agent_score})")

    if flood_count > 0:
        score += 2
        reasons.append("Flood detected")

    night_ratio = night_count / ip_count if ip_count > 0 else 0.0
    if night_count >= 2 and night_ratio >= 0.5:
        score += 3
        reasons.append(f"High night activity: {night_ratio:.0%} of requests between 0-5am")
    elif night_count >= 2 and night_ratio >= 0.2:
        score += 2
        reasons.append(f"Significant night activity: {night_ratio:.0%} of requests between 0-5am")
    elif night_count >= 1 and night_ratio >= 0.05:
        score += 1
        reasons.append(f"Night activity: {night_ratio:.0%} of requests between 0-5am")

    # Endpoint diversity: scanners enumerate many paths; legitimate clients stay focused.
    if path_diversity >= 50:
        score += 4
        reasons.append(f"High path diversity: {path_diversity} unique paths")
    elif path_diversity >= 20:
        score += 2
        reasons.append(f"Elevated path diversity: {path_diversity} unique paths")
    elif path_diversity >= 10:
        score += 1
        reasons.append(f"Moderate path diversity: {path_diversity} unique paths")
    if burst_count >= 10:
        score += 4
        reasons.append(f"Request burst: {burst_count} requests within 60 seconds")
    elif burst_count >= 5:
        score += 2
        reasons.append(f"Moderate burst: {burst_count} requests within 60 seconds")
    normalized = min(100, round(score * 100 / _MAX_RAW_SCORE))

    if normalized >= 70:
        level = "CRITICAL"
    elif normalized >= 40:
        level = "HIGH"
    elif normalized >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"ip": ip, "risk_level": level, "score": normalized, "reasons": reasons}

def build_prompt(entries):
    if not entries:
        return ""

    context_blocks = []
    for entry in entries:
        context_blocks.append(
            f"- IP: {entry['ip']}\n"
            f"  Risk Level: {entry['risk_level']}\n"
            f"  Score: {entry['score']}\n"
            f"  Reasons: {entry['reasons']}\n"
        )

    ips_list = ", ".join(entry["ip"] for entry in entries)
    return f"""
ROLE:
You are a Senior Cybersecurity Analyst.

TASK:
Classify the threat level and provide a recommendation for each of the following IPs: {ips_list}

CONTEXT:
{"".join(context_blocks)}
OUTPUT:
Return ONLY a JSON array with one object per IP, in the same order as listed above. No text before or after it:
[
  {{
    "ip": "<ip>",
    "risk_level": "<level>",
    "reasoning": ["reason 1", "reason 2"],
    "recommendation": "one action"
  }}
]
"""


def analyze_with_claude(entries):
    if not entries:
        return []

    client = Anthropic()
    prompt = build_prompt(entries)

    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=min(4096, 500 + 250 * len(entries)),
        system=(
            "Respond only in JSON format. Do not include any text, markdown, or explanation "
            "outside the JSON array."
        ),
        messages=[{"role": "user", "content": prompt}],
    )

    text = re.sub(r"```json|```", "", message.content[0].text).strip()
    parsed = json.loads(text)
    if isinstance(parsed, list):
        return parsed
    return [parsed]

def analyze_file(filepath: str, login_url: str = "/login"):
    ips = Counter()
    login_attempts = Counter()
    scanners = Counter()
    sql_injection = Counter()
    flood_ips = Counter()
    burst_ips = Counter()
    night_requests = Counter()
    suspicious_agents = Counter()
    first_seen = {}
    last_seen = {}
    errors_4xx = 0
    errors_5xx = 0
    errors_4xx_per_ip = Counter()
    errors_5xx_per_ip = Counter()
    ip_profiles = {}
    redirects = 0
    total_requests = 0
    parsed_lines = 0

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                parsed = parse_line(line)
                if not parsed:
                    continue
                parsed_lines += 1
                total_requests += 1
                if is_whitelisted(parsed["ip"]):
                    continue
                _record_ip_request(ip_profiles, parsed)
                ips[parsed["ip"]] += 1
                try:
                    dt = datetime.strptime(parsed["datetime"], "%d/%b/%Y:%H:%M:%S %z")
                    ip = parsed["ip"]
                    if ip not in first_seen or dt < first_seen[ip]:
                        first_seen[ip] = dt
                    if ip not in last_seen or dt > last_seen[ip]:
                        last_seen[ip] = dt
                    if dt.hour < 5:
                        night_requests[ip] += 1
                except:
                    pass
                if ips[parsed["ip"]] > FLOOD_THRESHOLD:
                    flood_ips[parsed["ip"]] = ips[parsed["ip"]]
                for path, path_weight in SCANNER_PATHS.items():
                    if path in parsed["url"]:
                        if parsed["status"] == 200:
                            scanners[parsed["ip"]] += 3 * path_weight
                        elif parsed["status"] == 401:
                            scanners[parsed["ip"]] += 2 * path_weight
                        elif parsed["status"] == 403:
                            scanners[parsed["ip"]] += 1 * path_weight
                        elif parsed["status"] in (404, 500, 502):
                            scanners[parsed["ip"]] += 0.5 * path_weight
                url_lower = parsed["url"].lower()
                for pattern, pattern_weight in SQL_PATTERNS.items():
                    if pattern in url_lower:
                        if parsed["status"] == 200:
                            sql_injection[parsed["ip"]] += 3 * pattern_weight
                        elif parsed["status"] == 401:
                            sql_injection[parsed["ip"]] += 2 * pattern_weight
                        elif parsed["status"] == 403:
                            sql_injection[parsed["ip"]] += 1 * pattern_weight
                        elif parsed["status"] in (404, 500, 502):
                            sql_injection[parsed["ip"]] += 0.5 * pattern_weight
                user_agent = (parsed.get("user_agent") or "").lower()
                for agent, agent_weight in SUSPICIOUS_AGENTS.items():
                    if agent in user_agent:
                        suspicious_agents[parsed["ip"]] += agent_weight
                if parsed["method"] == "POST" and parsed["url"] == login_url:
                    login_attempts[parsed["ip"]] += 1
                if 300 <= parsed["status"] < 400:
                    redirects += 1
                elif 400 <= parsed["status"] < 500:
                    errors_4xx += 1
                    errors_4xx_per_ip[parsed["ip"]] += 1
                elif 500 <= parsed["status"] < 600:
                    errors_5xx += 1
                    errors_5xx_per_ip[parsed["ip"]] += 1
    except FileNotFoundError:
        return {"error": "not_found", "filepath": filepath}
    except PermissionError:
        return {"error": "permission", "filepath": filepath}
    except Exception as e:
        return {"error": f"unexpected: {e}", "filepath": filepath}

    rates = {}
    for ip in ips:
        if ip in first_seen and ip in last_seen:
            duration_secs = (last_seen[ip] - first_seen[ip]).total_seconds()
            rates[ip] = ips[ip] / (duration_secs / 60) if duration_secs > 0 else float(ips[ip])
        else:
            rates[ip] = 0.0

    burst_ips = Counter()
    for ip, profile in ip_profiles.items():
        timestamps = []
    for ts in profile.get("timestamps", []):
        try:
            dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
            timestamps.append(dt)
        except:
            continue
        timestamps.sort()
        window = timedelta(seconds=60)
        burst_threshold = 10
        for i in range(len(timestamps)):
            window_requests = [t for t in timestamps[i:] if t - timestamps[i] <= window]
            if len(window_requests) >= burst_threshold:
                burst_ips[ip] = len(window_requests)
                break
    
    risk_report = []
    for ip in ips:
        profile = ip_profiles.get(ip, {})
        path_diversity = len(profile.get("unique_paths", ()))
        risk = classify_risk(
            ip,
            ips[ip],
            login_attempts.get(ip, 0),
            scanners.get(ip, 0),
            flood_ips.get(ip, 0),
            night_requests.get(ip, 0),
            errors_4xx_per_ip.get(ip, 0),
            suspicious_agents.get(ip, 0),
            rates.get(ip, 0.0),
            sql_injection.get(ip, 0),
            path_diversity,
            burst_ips.get(ip, 0),
        )
        if risk["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM"):
            risk_report.append(risk)

    risk_report.sort(key=lambda x: x["score"], reverse=True)

    return {
        "error": None,
        "filepath": filepath,
        "total_requests": total_requests,
        "parsed_lines": parsed_lines,
        "errors_4xx": errors_4xx,
        "errors_5xx": errors_5xx,
        "ips": ips,
        "login_attempts": dict(login_attempts),
        "scanners": dict(scanners),
        "sql_injection": dict(sql_injection),
        "suspicious_agents": dict(suspicious_agents),
        "flood_ips": dict(flood_ips),
        "night_requests": dict(night_requests),
        "errors_4xx_per_ip": dict(errors_4xx_per_ip),
        "errors_5xx_per_ip": dict(errors_5xx_per_ip),
        "ip_profiles": ip_profiles,
        "risk_report": risk_report,
    }

def load_blocklist(filepath):
    ips = set()
    with open(filepath, "r") as f:
        for line in f:
            ips.add(line.strip())
    return ips
blocklist = load_blocklist(os.path.join(os.path.dirname(__file__), "../../samples/blocklist.txt"))


def load_seen_ips(filepath: str = SEEN_IPS_FILE) -> dict[str, str]:
    if not os.path.isfile(filepath):
        return {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {ip: level for ip, level in data.items() if isinstance(level, str)}
        if isinstance(data, list):
            # Legacy format: IP list only; assume prior alert was at least MEDIUM.
            return {ip: "MEDIUM" for ip in data if isinstance(ip, str)}
        return {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_seen_ips(seen: dict[str, str], filepath: str = SEEN_IPS_FILE) -> None:
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(dict(sorted(seen.items())), f, indent=2)


def alert_ip(entry: dict) -> None:
    colors = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[97m", "LOW": "\033[92m"}
    reset = "\033[0m"
    color = colors.get(entry["risk_level"], reset)
    print(f"{color}[ALERT] [{entry['risk_level']}] {entry['ip']} (score: {entry['score']}){reset}")
    for reason in entry["reasons"]:
        print(f"  → {reason}")


def print_report(results, top: int = 10, bf_threshold: int = 3):
    if results.get("error"):
        err = results["error"]
        path = results.get("filepath")
        if err == "not_found":
            print(f"Error: file not found: {path}")
        elif err == "permission":
            print(f"Error: no permission to read: {path}")
        else:
            print(f"Error: {err}")
        return

    print(f"\nFile: {results['filepath']}")
    print(f"Total requests: {results['total_requests']}")
    print(f"Parsed lines: {results['parsed_lines']}")
    print(f"Errors 4xx: {results['errors_4xx']}")
    print(f"Errors 5xx: {results['errors_5xx']}")

    print(f"\nTop {top} IPs:")
    for ip, count in results["ips"].most_common(top):
        print(ip, count)

    suspects = [(ip, n) for ip, n in results["login_attempts"].items() if n > bf_threshold]
    if suspects:
        print(f"\nPossible brute force (>{bf_threshold} attempts):")
        for ip, n in sorted(suspects, key=lambda x: x[1], reverse=True):
            print(ip, n)

    scanners = results.get("scanners", {})
    if scanners:
        print("\nPossible scanners detected:")
        for ip, n in scanners.items():
            print(ip, n)

    risk_report = results.get("risk_report", [])
    if risk_report:
        print("\n=== RISK REPORT ===")
        seen_ips = load_seen_ips()
        seen_updated = False
        for entry in risk_report:
            if entry["score"] <= 0:
                continue
            ip = entry["ip"]
            level = entry["risk_level"]
            stored_level = seen_ips.get(ip)
            if (
                stored_level is not None
                and RISK_LEVELS.get(level, 0) <= RISK_LEVELS.get(stored_level, 0)
            ):
                continue
            alert_ip(entry)
            seen_ips[ip] = level
            seen_updated = True
        if seen_updated:
            save_seen_ips(seen_ips)

def export_pdf_report(results, output_path="report.pdf"):
    from reportlab.pdfgen import canvas
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter

    risk_colors = {
        "CRITICAL": colors.red,
        "HIGH": colors.orange,
        "MEDIUM": colors.grey,
    }

    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter
    y = height - 50

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "LogSec Toolkit - Security Report")
    y -= 22

    c.setFont("Helvetica", 10)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.drawString(50, y, f"Generated: {generated_at}")
    y -= 18
    c.drawString(50, y, f"File: {results['filepath']}")
    y -= 15
    c.drawString(50, y, f"Total requests: {results['total_requests']}")
    y -= 30

    risk_report = results.get("risk_report", [])

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Executive Summary")
    y -= 20

    c.setFont("Helvetica", 10)
    total_flagged = len(risk_report)
    c.drawString(50, y, f"Total flagged IPs: {total_flagged}")
    y -= 14

    level_counts = Counter(entry["risk_level"] for entry in risk_report)
    for level in ("CRITICAL", "HIGH", "MEDIUM"):
        c.drawString(50, y, f"  {level}: {level_counts.get(level, 0)}")
        y -= 12

    if risk_report:
        top = risk_report[0]
        first_reason = top["reasons"][0] if top.get("reasons") else "N/A"
        c.drawString(
            50,
            y,
            f"Top priority: {top['ip']} ({top['risk_level']}, score {top['score']})",
        )
        y -= 12
        c.drawString(50, y, f"  Primary reason: {first_reason}")
        y -= 14
    else:
        c.drawString(50, y, "Top priority: None")
        y -= 14

    y -= 16
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Risk Report")
    y -= 22

    for entry in risk_report:
        c.setFillColor(risk_colors.get(entry["risk_level"], colors.black))
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"[{entry['risk_level']}] {entry['ip']} (score: {entry['score']})")
        y -= 15
        c.setFont("Helvetica", 10)
        for reason in entry["reasons"]:
            c.drawString(70, y, f"- {reason}")
            y -= 12
        c.setFillColor(colors.black)
        y -= 10
        if y < 100:
            c.showPage()
            y = height - 50

    c.save()
    print(f"\nPDF report saved to: {output_path}")


def send_pdf_report(pdf_path: str, recipient_email: str) -> None:
    sender = os.getenv("GMAIL_SENDER")
    app_password = os.getenv("GMAIL_APP_PASSWORD")

    if not all([sender, app_password]):
        print("Configure GMAIL_SENDER and GMAIL_APP_PASSWORD in .env")
        return

    if not os.path.isfile(pdf_path):
        print(f"PDF not found: {pdf_path}")
        return

    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = recipient_email
    msg["Subject"] = "LogSec Toolkit - Security Report"
    msg.attach(MIMEText("Attached is the LogSec security analysis report.", "plain"))

    with open(pdf_path, "rb") as f:
        attachment = MIMEApplication(f.read(), _subtype="pdf")
        attachment.add_header(
            "Content-Disposition",
            "attachment",
            filename=os.path.basename(pdf_path),
        )
        msg.attach(attachment)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender, app_password)
        server.sendmail(sender, recipient_email, msg.as_string())

    print(f"PDF report sent to {recipient_email}")
