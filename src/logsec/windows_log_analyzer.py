import re
from typing import Optional


# Patterns ordered from most- to least-specific to avoid false matches.
_EVENT_ID_PATTERNS = [
    re.compile(r"Event\s+ID[:\s=]+(\d+)", re.IGNORECASE),
    re.compile(r"EventID[:\s=]+(\d+)", re.IGNORECASE),
    re.compile(r"\bID[:\s=]+(\d+)", re.IGNORECASE),
]

_IP_PATTERNS = [
    re.compile(r"Source\s+Network\s+Address[:\s=]+(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE),
    re.compile(r"(?:Source|Src|Client|Ip)\s*Address[:\s=]+(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE),
    re.compile(r"IpAddress[:\s=]+(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE),
    re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})"),
]

_TIMESTAMP_PATTERNS = [
    # ISO-8601: 2024-01-15T10:23:45(.000)(Z|+00:00)
    re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    # Common log: 2024-01-15 10:23:45
    re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"),
    # US format: 01/15/2024 10:23:45 AM/PM
    re.compile(r"(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\s*[AP]M)?)", re.IGNORECASE),
]


def _first_match(patterns: list, text: str) -> Optional[str]:
    for pattern in patterns:
        m = pattern.search(text)
        if m:
            return m.group(1).strip()
    return None


def parse_event(line: str) -> dict:
    """Parse a Windows Event Log line and return event_id, ip, and timestamp."""
    return {
        "event_id": _first_match(_EVENT_ID_PATTERNS, line),
        "ip": _first_match(_IP_PATTERNS, line),
        "timestamp": _first_match(_TIMESTAMP_PATTERNS, line),
    }


def detect_brute_force(events: list, threshold: int = 5) -> list:
    """Return IPs with more than `threshold` failed logon attempts (event_id 4625)."""
    counts: dict[str, int] = {}
    for event in events:
        if str(event.get("event_id")) == "4625":
            ip = event.get("ip")
            if ip:
                counts[ip] = counts.get(ip, 0) + 1
    return [ip for ip, count in counts.items() if count > threshold]


def generate_report(events: list, brute_force_ips: list) -> str:
    """Return a formatted report of flagged IPs and their failed logon counts."""
    flagged = set(brute_force_ips)
    counts: dict[str, int] = {}
    for event in events:
        if str(event.get("event_id")) == "4625":
            ip = event.get("ip")
            if ip and ip in flagged:
                counts[ip] = counts.get(ip, 0) + 1

    lines = ["Windows Event Log — Brute Force Report", "=" * 42]
    if not counts:
        lines.append("No flagged IPs found.")
    else:
        lines.append(f"{'IP Address':<20} {'Failed Logons':>13}")
        lines.append("-" * 35)
        for ip, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"{ip:<20} {count:>13}")
        lines.append("-" * 35)
        lines.append(f"{'Total flagged IPs:':<20} {len(counts):>13}")
    return "\n".join(lines)
