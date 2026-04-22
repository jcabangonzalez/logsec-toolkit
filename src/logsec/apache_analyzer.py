import re
import os
import json
import time
import requests
from collections import Counter
from dotenv import load_dotenv
from anthropic import Anthropic
from google import genai

load_dotenv()

log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\d+|-)'
)

def parse_line(line: str):
    match = log_pattern.match(line)
    if not match:
        return None
    data = match.groupdict()
    data["status"] = int(data["status"])
    data["size"] = 0 if data["size"] == "-" else int(data["size"])
    return data

def classify_risk(ip: str, ip_count: int, login_attempts: int, scanner_hits: int, flood_count: int) -> dict:
    score = 0
    reasons = []

    if ip_count >= 500:
        score += 2
        reasons.append(f"Alto volumen: {ip_count} requests")
    elif ip_count >= 100:
        score += 1
        reasons.append(f"Volumen elevado: {ip_count} requests")

    if login_attempts >= 10:
        score += 4
        reasons.append(f"Brute force probable: {login_attempts} intentos")
    elif login_attempts >= 3:
        score += 2
        reasons.append(f"Múltiples login attempts: {login_attempts}")

    if scanner_hits >= 3:
        score += 3
        reasons.append(f"Scanner de vulnerabilidades: {scanner_hits} paths sensibles")
    elif scanner_hits >= 1:
        score += 1
        reasons.append(f"Acceso a path sospechoso: {scanner_hits}")

    if flood_count > 0:
        score += 2
        reasons.append("Flood detectado")

    if score >= 7:
        level = "CRITICAL"
    elif score >= 4:
        level = "HIGH"
    elif score >= 2:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"ip": ip, "risk_level": level, "score": score, "reasons": reasons}

def analyze_file(filepath: str, login_url: str = "/login"):
    ips = Counter()
    login_attempts = Counter()
    scanners = Counter()
    flood_ips = Counter()
    errors_4xx = 0
    errors_5xx = 0
    redirects = 0
    flood_threshold = 10
    total_requests = 0
    parsed_lines = 0

    scanner_paths = ["/.env", "/.git", "/phpmyadmin", "/wp-admin"]

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                parsed = parse_line(line)
                if not parsed:
                    continue
                parsed_lines += 1
                total_requests += 1
                ips[parsed["ip"]] += 1
                if ips[parsed["ip"]] > flood_threshold:
                    flood_ips[parsed["ip"]] = ips[parsed["ip"]]
                if any(path in parsed["url"] for path in scanner_paths):
                    if parsed["status"] == 200:
                        scanners[parsed["ip"]] += 3
                    elif parsed["status"] == 401:
                        scanners[parsed["ip"]] += 2
                    elif parsed["status"] == 403:
                        scanners[parsed["ip"]] += 1
                    elif parsed["status"] == 404:
                        scanners[parsed["ip"]] += 0.5
                    elif parsed["status"] == 500:
                        scanners[parsed["ip"]] += 0.5
                    elif parsed["status"] == 502:
                        scanners[parsed["ip"]] += 0.5
                if parsed["method"] == "POST" and parsed["url"] == login_url:
                    login_attempts[parsed["ip"]] += 1
                if 300 <= parsed["status"] < 400:
                    redirects += 1
                elif 400 <= parsed["status"] < 500:
                    errors_4xx += 1
                elif 500 <= parsed["status"] < 600:
                    errors_5xx += 1

    except FileNotFoundError:
        return {"error": "not_found", "filepath": filepath}
    except PermissionError:
        return {"error": "permission", "filepath": filepath}
    except Exception as e:
        return {"error": f"unexpected: {e}", "filepath": filepath}

    risk_report = []
    for ip in ips:
        risk = classify_risk(ip, ips[ip], login_attempts.get(ip, 0), scanners.get(ip, 0), flood_ips.get(ip, 0))
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
        "flood_ips": dict(flood_ips),
        "risk_report": risk_report,
    }

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

