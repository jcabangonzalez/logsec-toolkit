import sys
import json
import subprocess
from types import SimpleNamespace

# Minimal MITRE mapper (directly included)
class MITREMapper:
    TECHNIQUES = {
        "T1190": {"name": "Exploit Public-Facing App", "patterns": ["' OR", "UNION SELECT", "--", "1=1"]},
        "T1595.002": {"name": "Vulnerability Scanning", "patterns": ["/wp-admin", "/phpmyadmin", "/.env", "sqlmap"]},
        "T1006": {"name": "Path Traversal", "patterns": ["../", "/etc/passwd"]}
    }
    def map_request(self, request, status_code, user_agent, ip, timestamp, failure_count=0):
        matches = []
        req_lower = request.lower()
        ua_lower = user_agent.lower()
        for tid, info in self.TECHNIQUES.items():
            for p in info["patterns"]:
                if p.lower() in req_lower or p.lower() in ua_lower:
                    matches.append({"technique_id": tid, "technique_name": info["name"], "pattern": p})
                    break
        if status_code in [401,403] and failure_count >= 5:
            matches.append({"technique_id": "T1110.001", "technique_name": "Password Guessing", "pattern": f"{failure_count} failures"})
        return matches

mitre = MITREMapper()

class OllamaTriage:
    def analyze(self, log_entry, mitre_techs):
        prompt = f"Return JSON only: risk (low/med/high/crit), action (block/monitor/ignore), summary. Log: {log_entry} MITRE: {mitre_techs}"
        try:
            result = subprocess.run(["ollama", "run", "qwen2.5-coder:latest", prompt], capture_output=True, text=True, timeout=30)
            return result.stdout.strip()
        except Exception as e:
            return json.dumps({"error": str(e)})

ollama = OllamaTriage()

def classify_risk(request, status_code, user_agent, ip, timestamp_str, failure_count=0, args=None):
    mitre_matches = mitre.map_request(request, status_code, user_agent, ip, timestamp_str, failure_count)
    result = {"ip": ip, "request": request, "status_code": status_code, "mitre_techniques": mitre_matches}
    if args and getattr(args, 'ollama', False):
        result["ai_triage"] = ollama.analyze(request, mitre_matches)
    return result

args = SimpleNamespace(ollama=True, mitre=True)

with open('test.log') as f:
    for line in f:
        parts = line.split()
        if len(parts) < 11:
            continue
        ip = parts[0]
        timestamp = parts[3].lstrip('[')
        method = parts[4].strip('"')
        path = parts[5]
        request = f"{method} {path}"
        status = int(parts[7])
        user_agent = parts[10].strip('"')
        result = classify_risk(request, status, user_agent, ip, timestamp, 0, args)
        print(result)
