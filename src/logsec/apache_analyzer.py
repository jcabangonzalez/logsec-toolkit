import re
import os
import json
import time
import requests
from collections import Counter
from datetime import datetime
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
_MAX_RAW_SCORE = 27

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

def parse_line(line: str):
    match = log_pattern.match(line)
    if not match:
        return None
    data = match.groupdict()
    data["status"] = int(data["status"])
    data["size"] = 0 if data["size"] == "-" else int(data["size"])
    return data

def classify_risk(ip: str, ip_count: int, login_attempts: int, scanner_hits: int, flood_count: int, night_count: int = 0, errors_4xx: int = 0, agent_score: int = 0, rate: float = 0.0) -> dict:
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

def build_prompt(entry):
    return f"""
ROLE:
You are a Senior Cybersecurity Analyst.

TASK:
Classify the threat level and provide a recommendation for IP {entry["ip"]}.

CONTEXT:
IP: {entry["ip"]}
Risk Level: {entry["risk_level"]}
Score: {entry["score"]}
Reasons: {entry["reasons"]}

OUTPUT:
Return ONLY this JSON object. No text before or after it:
{{
  "ip": "{entry["ip"]}",
  "risk_level": "{entry["risk_level"]}",
  "reasoning": ["reason 1", "reason 2"],
  "recommendation": "one action"
}}
"""

def analyze_with_claude(entry):
    client = Anthropic()
    prompt = build_prompt(entry)
    
    message = client.messages.create(
        model="claude-haiku-20240307",
        max_tokens=1000,
        system="Respond only in JSON format. Do not include any text, markdown, or explanation outside the JSON object.",
        messages=[
            {"role": "user", "content": prompt}
        ]
    )
    
    text = message.content[0].text
    # Strip markdown code fences if present
    text = re.sub(r"```json|```", "", text).strip()
    return text
    
    return message.content[0].text

def analyze_file(filepath: str, login_url: str = "/login"):
    ips = Counter()
    login_attempts = Counter()
    scanners = Counter()
    flood_ips = Counter()
    night_requests = Counter()
    suspicious_agents = Counter()
    first_seen = {}
    last_seen = {}
    errors_4xx = 0
    errors_5xx = 0
    errors_4xx_per_ip = Counter()
    errors_5xx_per_ip = Counter()
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

    risk_report = []
    for ip in ips:
        risk = classify_risk(ip, ips[ip], login_attempts.get(ip, 0), scanners.get(ip, 0), flood_ips.get(ip, 0), night_requests.get(ip, 0), errors_4xx_per_ip.get(ip, 0), suspicious_agents.get(ip, 0), rates.get(ip, 0.0))
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
        "suspicious_agents": dict(suspicious_agents),
        "flood_ips": dict(flood_ips),
        "night_requests": dict(night_requests),
        "errors_4xx_per_ip": dict(errors_4xx_per_ip),
        "errors_5xx_per_ip": dict(errors_5xx_per_ip),
        "risk_report": risk_report,
    }

def load_blocklist(filepath):
    ips = set()
    with open(filepath, "r") as f:
        for line in f:
            ips.add(line.strip())
    return ips
blocklist = load_blocklist("../samples/blocklist.txt")

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
        for entry in risk_report:
            if entry["score"] > 0:
                colors = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[97m", "LOW": "\033[92m"}
                reset = "\033[0m"
                color = colors.get(entry['risk_level'], reset)
                print(f"{color}[{entry['risk_level']}] {entry['ip']} (score: {entry['score']}){reset}")
                for reason in entry["reasons"]:
                    print(f"  → {reason}")

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



