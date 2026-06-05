import sys
sys.path.insert(0, 'src')
from types import SimpleNamespace

# Minimal classify_risk if missing
try:
    from logsec.apache_analyzer import classify_risk
except ImportError:
    def classify_risk(request, status_code, user_agent, ip, timestamp_str, failure_count=0, args=None):
        return {"ip": ip, "request": request, "status_code": status_code, "user_agent": user_agent}

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
