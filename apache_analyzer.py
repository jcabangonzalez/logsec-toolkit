import jsonlines
from dataclasses import dataclass

@dataclass
class LogEntry:
    ip: str
    timestamp: str
    method: str
    path: str
    status_code: int
    risk_score: float
    risk_level: str
    mitre_tactic: str | None = None

def format_jsonl_entry(entry: LogEntry) -> dict:
    return {
        "ip": entry.ip,
        "timestamp": entry.timestamp,
        "method": entry.method,
        "path": entry.path,
        "status_code": entry.status_code,
        "risk_score": entry.risk_score,
        "risk_level": entry.risk_level,
        "mitre_tactic": entry.mitre_tactic
    }

def analyze_file(
    filepath: str,
    login_url: str = "/login",
    bf_threshold: int | None = None,
    flood_threshold: int | None = None,
    burst_threshold: int | None = None,
    risk_score_min: int | None = None,
    mitre: bool = False,
    include_internal: bool = False,
) -> list[dict]:
    results = []
    
    # Existing analysis logic...
    
    for result in analyzed_results:
        log_entry = LogEntry(
            ip=result["ip"],
            timestamp=result["timestamp"],
            method=result["method"],
            path=result["path"],
            status_code=result["status_code"],
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            mitre_tactic=result.get("mitre_tactic")
        )
        results.append(format_jsonl_entry(log_entry))

    return results
