import argparse
import ipaddress
import re
import os
import json
import sys
import time
import smtplib
import requests
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any
from logsec.mitre_mapper import MITREMapper
from logsec.ollama_ai import OllamaTriage
from anthropic import Anthropic
from dotenv import load_dotenv
from google import genai
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

try:
    import yaml
except ImportError:
    yaml = None

load_dotenv()

_PACKAGE_DIR = Path(__file__).resolve().parent
_DEFAULT_CONFIG_PATHS = (
    Path.cwd() / "config.yaml",
    _PACKAGE_DIR / "config.yaml",
    _PACKAGE_DIR.parent.parent / "config.yaml",
)

log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>.+?) (?P<protocol>HTTP/[^ "]+)" '
    r'(?P<status>\d+) (?P<size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

FLOOD_THRESHOLD = 10
BURST_THRESHOLD = 10
BF_THRESHOLD = 3
RATE_ALERT_THRESHOLD = 30
RISK_SCORE_MIN = 15
_MAX_RAW_SCORE = 30
_RECENT_REQUESTS_MAX = 20
SEEN_IPS_FILE = str(_PACKAGE_DIR / "seen_ips.json")
RISK_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Per-IP request sequences capture order and context (method, URL, status, time).
# Isolated signals (e.g. one 404 or one login POST) are noisy; ordered sequences
# support behavioral correlation—recon then exploit, scan bursts, auth-then-admin—
# which improves detection quality when attack-chain rules are added later.

_whitelist_exact: set[str] = set()
_whitelist_prefixes: list[str] = []
_whitelist_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_slack_webhook: str | None = None
_discord_webhook: str | None = None
_email_enabled: bool = True

GEO_CACHE_FILE = str(_PACKAGE_DIR / "geo_cache.json")
_geo_enabled: bool = True
_geo_provider: str = "ip-api.com"
_geo_cache_days: int = 30
_geo_timeout: float = 2.0
_geo_cache: dict[str, Any] | None = None


@dataclass
class ToolkitConfig:
    flood: int = 10
    burst: int = 10
    brute_force: int = 3
    rate_alert: int = 30
    risk_score_min: int = 15
    whitelist: list[str] = field(default_factory=list)
    scan_paths: dict[str, int] = field(default_factory=dict)
    slack_webhook: str | None = None
    discord_webhook: str | None = None
    email_enabled: bool = True
    geo_enabled: bool = True
    geo_provider: str = "ip-api.com"
    geo_cache_days: int = 30
    geo_timeout_seconds: float = 2.0


def _expand_env(value: str) -> str:
    if not isinstance(value, str):
        return value

    def repl(match: re.Match) -> str:
        key = match.group(1)
        return os.environ.get(key, "")

    return re.sub(r"\$\{([^}]+)\}", repl, value)


def _parse_whitelist_entry(entry: str) -> None:
    entry = entry.strip()
    if not entry:
        return
    if "/" in entry:
        try:
            _whitelist_networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass
        return
    if entry.endswith("."):
        _whitelist_prefixes.append(entry)
    else:
        _whitelist_exact.add(entry)


def _apply_whitelist(entries: list[str] | None = None) -> None:
    global _whitelist_exact, _whitelist_prefixes, _whitelist_networks
    _whitelist_exact = set()
    _whitelist_prefixes = []
    _whitelist_networks = []
    defaults = [
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
    ]
    for entry in entries if entries is not None else defaults:
        _parse_whitelist_entry(entry)


_apply_whitelist(None)


def load_config(config_path: str | Path | None = None) -> ToolkitConfig:
    """Load YAML config and apply thresholds, whitelist, and scan paths."""
    global FLOOD_THRESHOLD, BURST_THRESHOLD, BF_THRESHOLD, RATE_ALERT_THRESHOLD
    global RISK_SCORE_MIN, SCANNER_PATHS, _slack_webhook, _discord_webhook, _email_enabled
    global _geo_enabled, _geo_provider, _geo_cache_days, _geo_timeout

    cfg = ToolkitConfig()
    path = Path(config_path) if config_path else None
    if path is None:
        for candidate in _DEFAULT_CONFIG_PATHS:
            if candidate.is_file():
                path = candidate
                break

    if path is None or not path.is_file():
        return cfg

    if yaml is None:
        print("Warning: PyYAML not installed; ignoring config file. pip install pyyaml", file=sys.stderr)
        return cfg

    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    thresholds = raw.get("thresholds") or {}
    cfg.flood = int(thresholds.get("flood", cfg.flood))
    cfg.burst = int(thresholds.get("burst", cfg.burst))
    cfg.brute_force = int(thresholds.get("brute_force", cfg.brute_force))
    cfg.rate_alert = int(thresholds.get("rate_alert", cfg.rate_alert))
    cfg.risk_score_min = int(thresholds.get("risk_score_min", cfg.risk_score_min))

    cfg.whitelist = list(raw.get("whitelist") or [])
    scan_list = raw.get("scan_paths")
    if scan_list:
        cfg.scan_paths = {p: 2 for p in scan_list}

    integrations = raw.get("integrations") or {}
    cfg.slack_webhook = _expand_env(integrations.get("slack_webhook") or "") or None
    cfg.discord_webhook = _expand_env(integrations.get("discord_webhook") or "") or None
    cfg.email_enabled = bool(integrations.get("email_enabled", True))

    geoip = raw.get("geoip") or {}
    cfg.geo_enabled = bool(geoip.get("enabled", True))
    cfg.geo_provider = str(geoip.get("provider", "ip-api.com"))
    cfg.geo_cache_days = int(geoip.get("cache_days", 30))
    cfg.geo_timeout_seconds = float(geoip.get("timeout_seconds", 2))

    FLOOD_THRESHOLD = cfg.flood
    BURST_THRESHOLD = cfg.burst
    BF_THRESHOLD = cfg.brute_force
    RATE_ALERT_THRESHOLD = cfg.rate_alert
    RISK_SCORE_MIN = cfg.risk_score_min

    if cfg.whitelist:
        _apply_whitelist(cfg.whitelist)
    if cfg.scan_paths:
        SCANNER_PATHS.clear()
        SCANNER_PATHS.update(cfg.scan_paths)

    _slack_webhook = cfg.slack_webhook
    _discord_webhook = cfg.discord_webhook
    _email_enabled = cfg.email_enabled
    _geo_enabled = cfg.geo_enabled
    _geo_provider = cfg.geo_provider
    _geo_cache_days = cfg.geo_cache_days
    _geo_timeout = cfg.geo_timeout_seconds
    return cfg


def configure_geoip(
    *,
    enabled: bool | None = None,
    provider: str | None = None,
    cache_days: int | None = None,
    timeout_seconds: float | None = None,
) -> None:
    """Apply runtime geo-IP settings (CLI flags override config)."""
    global _geo_enabled, _geo_provider, _geo_cache_days, _geo_timeout
    if enabled is not None:
        _geo_enabled = enabled
    if provider is not None:
        _geo_provider = provider
    if cache_days is not None:
        _geo_cache_days = cache_days
    if timeout_seconds is not None:
        _geo_timeout = timeout_seconds


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _load_geo_cache() -> dict[str, Any]:
    global _geo_cache
    if _geo_cache is not None:
        return _geo_cache
    if not os.path.isfile(GEO_CACHE_FILE):
        _geo_cache = {}
        return _geo_cache
    try:
        with open(GEO_CACHE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        _geo_cache = data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        _geo_cache = {}
    return _geo_cache


def _save_geo_cache(cache: dict[str, Any]) -> None:
    global _geo_cache
    _geo_cache = cache
    try:
        with open(GEO_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except OSError:
        pass


def _geo_cache_get(ip: str) -> dict | None:
    cache = _load_geo_cache()
    entry = cache.get(ip)
    if not entry:
        return None
    cached_at = entry.get("cached_at")
    if not cached_at:
        return None
    try:
        stored = datetime.fromisoformat(cached_at)
    except (ValueError, TypeError):
        return None
    if datetime.now() - stored > timedelta(days=_geo_cache_days):
        return None
    data = entry.get("data")
    return data if isinstance(data, dict) else None


def _geo_cache_set(ip: str, data: dict | None) -> None:
    cache = dict(_load_geo_cache())
    cache[ip] = {"cached_at": datetime.now().isoformat(), "data": data}
    _save_geo_cache(cache)


def _fetch_geoip_ip_api(ip: str) -> dict | None:
    url = f"http://ip-api.com/json/{ip}"
    params = {"fields": "status,message,country,countryCode,city,lat,lon"}
    resp = requests.get(url, params=params, timeout=_geo_timeout)
    resp.raise_for_status()
    body = resp.json()
    if body.get("status") != "success":
        return None
    return {
        "country": body.get("country") or "Unknown",
        "country_code": (body.get("countryCode") or "XX").upper(),
        "city": body.get("city") or "",
        "lat": body.get("lat"),
        "lon": body.get("lon"),
    }


def _fetch_geoip_freegeoip(ip: str) -> dict | None:
    url = f"https://freegeoip.app/json/{ip}"
    resp = requests.get(url, timeout=_geo_timeout)
    resp.raise_for_status()
    body = resp.json()
    return {
        "country": body.get("country_name") or body.get("country") or "Unknown",
        "country_code": (body.get("country_code") or "XX").upper(),
        "city": body.get("city") or "",
        "lat": body.get("latitude") if body.get("latitude") is not None else body.get("lat"),
        "lon": body.get("longitude") if body.get("longitude") is not None else body.get("lon"),
    }


def get_geoip(ip: str) -> dict | None:
    """Resolve country/city/coordinates for an IP; uses file cache and handles private IPs."""
    if not _geo_enabled:
        return None
    if _is_private_ip(ip):
        return {"country": "Private", "country_code": "XX", "city": "", "lat": None, "lon": None}

    cached = _geo_cache_get(ip)
    if cached is not None:
        return cached

    provider = (_geo_provider or "ip-api.com").lower()
    try:
        if "freegeoip" in provider:
            data = _fetch_geoip_freegeoip(ip)
        else:
            data = _fetch_geoip_ip_api(ip)
    except (requests.RequestException, ValueError, KeyError):
        _geo_cache_set(ip, None)
        return None

    if data:
        _geo_cache_set(ip, data)
    return data


def country_flag(country_code: str) -> str:
    code = (country_code or "XX").upper()
    if len(code) != 2 or not code.isalpha() or code == "XX":
        return "🏴"
    return "".join(chr(0x1F1E6 - 0x41 + ord(c)) for c in code)


def format_geo_country(geo: dict | None, *, short: bool = False) -> str:
    if not geo:
        return "—"
    code = geo.get("country_code", "XX")
    name = geo.get("country", "Unknown")
    flag = country_flag(code)
    if short and code and code != "XX":
        return f"{flag} {code}"
    return f"{flag} {name}"


def aggregate_geo_stats(risk_report: list) -> dict[str, int]:
    """Count flagged IPs per country name."""
    stats: Counter[str] = Counter()
    for entry in risk_report:
        geo = entry.get("geo")
        country = geo.get("country", "Unknown") if geo else "Unknown"
        stats[country] += 1
    return dict(stats)


def _country_codes_from_report(risk_report: list) -> dict[str, str]:
    codes: dict[str, str] = {}
    for entry in risk_report:
        geo = entry.get("geo")
        if not geo:
            continue
        country = geo.get("country", "Unknown")
        codes[country] = geo.get("country_code", "XX")
    return codes


def render_country_chart(
    geo_stats: dict[str, int],
    *,
    country_codes: dict[str, str] | None = None,
    bar_width: int = 20,
):
    """Rich panel: top 5 countries by flagged IP count plus Others."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    country_codes = country_codes or {}
    total = sum(geo_stats.values())
    if total <= 0:
        return Panel("No geo data for flagged IPs", title="🌍 Attack Origins by Country", border_style="cyan")

    sorted_items = sorted(geo_stats.items(), key=lambda x: x[1], reverse=True)
    top5 = sorted_items[:5]
    others_count = sum(count for _, count in sorted_items[5:])

    rows = Table.grid(padding=(0, 1))
    rows.add_column(width=28)
    rows.add_column()
    rows.add_column(justify="right", width=12)

    max_count = top5[0][1] if top5 else 1

    for country, count in top5:
        code = country_codes.get(country, "XX")
        pct = count / total * 100
        label = f"{country_flag(code)} {country}"
        bar = Text(_bar(count, max_count, width=bar_width), style="cyan")
        rows.add_row(label, bar, f"{count} ({pct:.0f}%)")

    if others_count > 0:
        pct = others_count / total * 100
        bar = Text(_bar(others_count, max_count, width=bar_width), style="dim")
        rows.add_row("Others", bar, f"{others_count} ({pct:.0f}%)")

    return Panel(rows, title="🌍 Attack Origins by Country", border_style="cyan")


def _risk_badge(level: str) -> str:
    return {
        "CRITICAL": "🔴 CRIT",
        "HIGH": "🟡 HIGH",
        "MEDIUM": "🟠 MED",
        "LOW": "🟢 LOW",
    }.get(level, level)


def is_whitelisted(ip: str) -> bool:
    if ip in _whitelist_exact:
        return True
    if any(ip.startswith(prefix) for prefix in _whitelist_prefixes):
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _whitelist_networks)
    except ValueError:
        return False

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
    # UNION-based extraction
    "union select": 3,
    "union%20select": 3,
    "union+select": 3,
    "from users": 3,
    "from+users": 3,
    "from information_schema": 3,
    # Boolean conditions
    "or 1=1": 3,
    "or%201=1": 3,
    "or+1=1": 3,
    "and 1=1": 2,
    "and+1=1": 2,
    "and 1=2": 2,
    "and+1=2": 2,
    "' or '": 2,
    "%27%20or%20": 2,
    "%27+or+": 2,
    # Column enumeration
    "order by": 2,
    "order+by": 2,
    "order%20by": 2,
    # Stacked / termination
    "drop table": 3,
    ";--": 2,
    "';--": 2,
    # Time-based blind
    "sleep(": 2,
    "benchmark(": 2,
    "waitfor delay": 2,
    "randomblob(": 2,
    "pg_sleep(": 2,
    # Fingerprinting
    "@@version": 2,
    "sqlite_version": 2,
    "information_schema": 2,
    # String manipulation (lower weight — broad)
    "concat(": 1,
    "char(": 1,
    "select null": 1,
    "select+null": 1,
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
        ip_profiles[ip]["sample_request"] = parsed["url"]
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


def classify_risk(
    ip: str,
    ip_count: int,
    login_attempts: int,
    scanner_hits: int,
    flood_count: int,
    night_count: int = 0,
    errors_4xx: int = 0,
    agent_score: int = 0,
    rate: float = 0.0,
    sql_hits: int = 0,
    path_diversity: int = 0,
    burst_count: int = 0,
    bf_threshold: int | None = None,
    include_geo: bool = False,
    include_internal: bool = False,
) -> dict:
    bf_threshold = BF_THRESHOLD if bf_threshold is None else bf_threshold
    if not include_internal and is_whitelisted(ip):
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
    elif login_attempts >= bf_threshold:
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

    if login_attempts >= bf_threshold and scanner_hits >= 1:
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

    result: dict[str, Any] = {"ip": ip, "risk_level": level, "score": normalized, "reasons": reasons}
    if include_geo and _geo_enabled:
        geo = get_geoip(ip)
        if geo:
            result["geo"] = geo
    return result

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

def analyze_with_ollama(entries, model: str = "qwen2.5-coder:latest"):
    if not entries:
        return []
    triage = OllamaTriage(model=model)
    prompt = build_prompt(entries)
    return triage.triage_batch(entries, prompt)


def analyze_file(
    filepath: str,
    login_url: str = "/login",
    *,
    bf_threshold: int | None = None,
    flood_threshold: int | None = None,
    burst_threshold: int | None = None,
    risk_score_min: int | None = None,
    mitre: bool = False,
    include_internal: bool = False,
):
    bf_threshold = BF_THRESHOLD if bf_threshold is None else bf_threshold
    flood_threshold = FLOOD_THRESHOLD if flood_threshold is None else flood_threshold
    burst_threshold = BURST_THRESHOLD if burst_threshold is None else burst_threshold
    risk_score_min = RISK_SCORE_MIN if risk_score_min is None else risk_score_min
    _wl_check = (lambda _ip: False) if include_internal else is_whitelisted
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
    mitre_mapper = MITREMapper()
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                parsed = parse_line(line)
                if not parsed:
                    continue
                parsed_lines += 1
                total_requests += 1
                if _wl_check(parsed["ip"]):
                    continue
                _record_ip_request(ip_profiles, parsed)
                mitre_matches = mitre_mapper.map_request(
                    request=parsed["url"],
                    status_code=parsed["status"],
                    user_agent=parsed.get("user_agent") or "",
                    ip=parsed["ip"],
                    timestamp=_parse_log_datetime(parsed["datetime"]) or datetime.now().astimezone(),
                    failure_count=login_attempts.get(parsed["ip"], 0),
                    response_size=parsed.get("size") or 0,
                )
                if mitre_matches:
                    ip_profiles[parsed["ip"]]["mitre"] = ip_profiles[parsed["ip"]].get("mitre", []) + mitre_matches
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
                if ips[parsed["ip"]] > flood_threshold:
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
            bf_threshold=bf_threshold,
            include_geo=False,
            include_internal=include_internal,
        )
        if risk["score"] >= risk_score_min and risk["score"] > 0:
            if _geo_enabled:
                geo = get_geoip(ip)
                if geo:
                    risk["geo"] = geo
            risk_report.append(risk)

    risk_report.sort(key=lambda x: x["score"], reverse=True)

    return {
        "login_url": login_url,
        "bf_threshold": bf_threshold,
        "risk_score_min": risk_score_min,
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
        "mitre_mapper": mitre_mapper,
    }

def load_blocklist(filepath):
    ips = set()
    with open(filepath, "r") as f:
        for line in f:
            ips.add(line.strip())
    return ips
_blocklist_path = _PACKAGE_DIR.parent.parent / "samples" / "blocklist.txt"
try:
    blocklist = load_blocklist(_blocklist_path)
except FileNotFoundError:
    blocklist = set()


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


def _notify_webhooks(entry: dict) -> None:
    geo = entry.get("geo") or {}
    country = geo.get("country") or "Unknown"
    text = (
        f"[{entry['risk_level']}] {entry['ip']} ({country}) (score: {entry['score']})\n"
        + "\n".join(f"- {r}" for r in entry.get("reasons", []))
    )
    payload = {
        "text": text,
        "country": country,
        "country_code": geo.get("country_code"),
        "city": geo.get("city"),
    }
    if _slack_webhook:
        try:
            requests.post(_slack_webhook, json=payload, timeout=5)
        except requests.RequestException:
            pass
    if _discord_webhook:
        try:
            requests.post(_discord_webhook, json={"content": text}, timeout=5)
        except requests.RequestException:
            pass


def alert_ip(entry: dict) -> None:
    colors = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[97m", "LOW": "\033[92m"}
    reset = "\033[0m"
    color = colors.get(entry["risk_level"], reset)
    geo = entry.get("geo") or {}
    country = geo.get("country")
    location = f" ({country})" if country else ""
    level_icons = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🟠", "LOW": "🟢"}
    icon = level_icons.get(entry["risk_level"], "")
    first_reason = entry.get("reasons", [None])[0]
    reason_suffix = f" - {first_reason}" if first_reason else ""
    print(
        f"{color}{icon} [{entry['risk_level']}] {entry['ip']}{location}{reason_suffix} "
        f"(score: {entry['score']}){reset}"
    )
    for reason in entry["reasons"]:
        print(f"  → {reason}")
    _notify_webhooks(entry)


def format_json_report(results: dict, top: int = 10) -> str:
    risk_report = results.get("risk_report") or []
    return json.dumps(
        {
            "filepath": results.get("filepath"),
            "total_requests": results.get("total_requests"),
            "parsed_lines": results.get("parsed_lines"),
            "errors_4xx": results.get("errors_4xx"),
            "errors_5xx": results.get("errors_5xx"),
            "top_ips": results["ips"].most_common(top) if results.get("ips") else [],
            "risk_report": risk_report,
            "login_attempts": results.get("login_attempts", {}),
            "scanners": results.get("scanners", {}),
            "sql_injection": results.get("sql_injection", {}),
        },
        indent=2,
        default=str,
    )


def print_report(
    results,
    top: int = 10,
    bf_threshold: int = 3,
    threshold: int | None = None,
):
    threshold = RISK_SCORE_MIN if threshold is None else threshold
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

    risk_report = [e for e in results.get("risk_report", []) if e.get("score", 0) >= threshold]
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
    if not _email_enabled:
        print("Email delivery disabled in config (integrations.email_enabled: false)")
        return

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


def _parse_log_datetime(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    except (ValueError, TypeError):
        return None


def _url_has_sqli(url: str) -> bool:
    url_lower = url.lower()
    return any(pattern in url_lower for pattern in SQL_PATTERNS)


def _url_hits_scanner(url: str) -> str | None:
    for path in SCANNER_PATHS:
        if path in url:
            return path
    return None


def _monitor_alert(
    ip: str,
    reasons: list[str],
    level: str = "HIGH",
    score: int = 50,
    alerted_ips: dict | None = None,
    alert_keys: set | None = None,
    dedupe_key: str | None = None,
) -> dict:
    if alert_keys is not None and dedupe_key and dedupe_key in alert_keys:
        return None
    entry: dict[str, Any] = {"ip": ip, "risk_level": level, "score": score, "reasons": reasons}
    if _geo_enabled:
        geo = get_geoip(ip)
        if geo:
            entry["geo"] = geo
    alert_ip(entry)
    if alert_keys is not None and dedupe_key:
        alert_keys.add(dedupe_key)
    if alerted_ips is not None:
        prev = alerted_ips.get(ip)
        if prev is None or entry["score"] > prev.get("score", 0):
            alerted_ips[ip] = entry
    return entry


def monitor_log(
    log_path: str,
    login_url: str = "/login",
    *,
    rate_threshold: int | None = None,
    dashboard: bool = False,
    dashboard_refresh: float = 3.0,
) -> dict[str, dict]:
    """
    Tail a log file and alert on high-rate traffic, SQLi, scanner paths, and login floods.
    Returns a dict of alerted IPs (summary after Ctrl+C).
    """
    rate_threshold = RATE_ALERT_THRESHOLD if rate_threshold is None else rate_threshold
    window_seconds = 60
    login_window_seconds = 30
    login_post_threshold = 5

    # Per-IP: deque of request timestamps (last 60s)
    ip_windows: dict[str, deque] = defaultdict(lambda: deque())
    # Per-IP: deque of login POST timestamps (last 30s)
    login_windows: dict[str, deque] = defaultdict(lambda: deque())
    alerted_ips: dict[str, dict] = {}
    alert_keys: set[str] = set()
    monitor_stats: dict[str, Any] = {
        "total_requests": 0,
        "errors_4xx": 0,
        "risk_report": [],
        "scanners": Counter(),
        "sql_injection": Counter(),
        "login_attempts": Counter(),
        "ips": Counter(),
        "filepath": log_path,
        "monitor_mode": True,
    }

    def prune_deque(dq: deque, now: datetime, max_age: float) -> None:
        while dq and (now - dq[0]).total_seconds() > max_age:
            dq.popleft()

    def process_parsed(parsed: dict, now: datetime | None = None) -> None:
        if is_whitelisted(parsed["ip"]):
            return
        ip = parsed["ip"]
        monitor_stats["total_requests"] += 1
        monitor_stats["ips"][ip] += 1
        if 400 <= parsed["status"] < 500:
            monitor_stats["errors_4xx"] += 1

        ts = _parse_log_datetime(parsed["datetime"]) or now or datetime.now().astimezone()
        ip_windows[ip].append(ts)
        prune_deque(ip_windows[ip], ts, window_seconds)

        req_count = len(ip_windows[ip])
        if req_count >= rate_threshold:
            entry = _monitor_alert(
                ip,
                [f"Rate exceeded: {req_count} requests in {window_seconds}s (threshold {rate_threshold}/min)"],
                level="CRITICAL" if req_count >= rate_threshold * 2 else "HIGH",
                score=min(100, 40 + req_count),
                alerted_ips=alerted_ips,
                alert_keys=alert_keys,
                dedupe_key=f"rate:{ip}",
            )
            if entry:
                monitor_stats["risk_report"].append(entry)

        if _url_has_sqli(parsed["url"]):
            monitor_stats["sql_injection"][ip] += 1
            entry = _monitor_alert(
                ip,
                [f"SQL injection pattern in URL: {parsed['url'][:120]}"],
                level="CRITICAL",
                score=85,
                alerted_ips=alerted_ips,
                alert_keys=alert_keys,
                dedupe_key=f"sqli:{ip}",
            )
            if entry:
                monitor_stats["risk_report"].append(entry)

        scan_path = _url_hits_scanner(parsed["url"])
        if scan_path:
            monitor_stats["scanners"][ip] += 1
            entry = _monitor_alert(
                ip,
                [f"Scanner path accessed: {scan_path}"],
                level="HIGH",
                score=70,
                alerted_ips=alerted_ips,
                alert_keys=alert_keys,
                dedupe_key=f"scan:{ip}:{scan_path}",
            )
            if entry:
                monitor_stats["risk_report"].append(entry)

        if parsed["method"] == "POST" and parsed["url"] == login_url:
            login_windows[ip].append(ts)
            prune_deque(login_windows[ip], ts, login_window_seconds)
            monitor_stats["login_attempts"][ip] += 1
            posts = len(login_windows[ip])
            if posts >= login_post_threshold:
                entry = _monitor_alert(
                    ip,
                    [f"Brute force: {posts} POSTs to {login_url} in {login_window_seconds}s"],
                    level="CRITICAL",
                    score=90,
                    alerted_ips=alerted_ips,
                    alert_keys=alert_keys,
                    dedupe_key=f"bf:{ip}",
                )
                if entry:
                    monitor_stats["risk_report"].append(entry)

    def tail_loop(live=None) -> None:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            print(f"Monitoring {log_path} (Ctrl+C to stop)...")
            while True:
                line = f.readline()
                if line:
                    parsed = parse_line(line)
                    if parsed:
                        process_parsed(parsed)
                    if live is not None:
                        live.update(show_dashboard(monitor_stats, return_renderable=True))
                else:
                    if live is not None:
                        live.update(show_dashboard(monitor_stats, return_renderable=True))
                    time.sleep(0.25)

    try:
        if dashboard:
            from rich.live import Live

            with Live(
                show_dashboard(monitor_stats, return_renderable=True),
                refresh_per_second=4,
                screen=False,
            ) as live:
                tail_loop(live=live)
        else:
            tail_loop()
    except KeyboardInterrupt:
        print("\n--- Monitor stopped ---")
    except FileNotFoundError:
        print(f"Error: file not found: {log_path}", file=sys.stderr)
        return {}
    except PermissionError:
        print(f"Error: no permission to read: {log_path}", file=sys.stderr)
        return {}

    if alerted_ips:
        print(f"\nSummary: {len(alerted_ips)} IP(s) alerted during this session")
        for ip, entry in sorted(alerted_ips.items(), key=lambda x: x[1].get("score", 0), reverse=True):
            print(f"  {entry['risk_level']:8} {ip} (score {entry['score']})")
    else:
        print("\nNo alerts during this session.")

    return alerted_ips


def _risk_style(level: str) -> str:
    from rich.style import Style

    return {
        "CRITICAL": Style(color="red", bold=True),
        "HIGH": Style(color="yellow", bold=True),
        "MEDIUM": Style(color="white"),
        "LOW": Style(color="green"),
    }.get(level, Style())


def _bar(value: int, maximum: int, width: int = 24) -> str:
    if maximum <= 0:
        return "░" * width
    filled = min(width, int(width * value / maximum))
    return "█" * filled + "░" * (width - filled)


def show_dashboard(results: dict, return_renderable: bool = False):
    """Rich terminal dashboard for analysis or live monitor results."""
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    total_requests = results.get("total_requests", 0)
    errors_4xx = results.get("errors_4xx", 0)
    risk_report = results.get("risk_report") or []
    flagged = len(risk_report)
    error_rate = (errors_4xx / total_requests * 100) if total_requests else 0.0

    gauges = Table.grid(padding=(0, 2))
    gauges.add_row(
        "Total requests",
        Text(_bar(total_requests, max(total_requests, 1)), style="cyan"),
        str(total_requests),
    )
    gauges.add_row(
        "Error rate (4xx)",
        Text(_bar(int(error_rate), 100), style="red" if error_rate > 10 else "yellow"),
        f"{error_rate:.1f}%",
    )
    gauges.add_row(
        "Flagged IPs",
        Text(_bar(flagged, max(flagged, 10) or 10), style="magenta"),
        str(flagged),
    )

    ip_table = Table(title="Top Attacking IPs", expand=True)
    ip_table.add_column("IP", style="bold")
    ip_table.add_column("Risk")
    ip_table.add_column("Score", justify="right")
    ip_table.add_column("Reasons", overflow="fold")
    ip_table.add_column("Country")

    entries = sorted(risk_report, key=lambda e: e.get("score", 0), reverse=True)[:10]
    if not entries and results.get("ips"):
        for ip, count in results["ips"].most_common(10):
            geo = get_geoip(ip) if _geo_enabled else None
            ip_table.add_row(
                ip,
                "—",
                "—",
                f"{count} requests",
                format_geo_country(geo, short=True),
            )
    else:
        for entry in entries:
            level = entry.get("risk_level", "LOW")
            reasons = "; ".join(entry.get("reasons", [])[:2]) or "—"
            ip_table.add_row(
                entry["ip"],
                _risk_badge(level),
                str(entry.get("score", 0)),
                reasons,
                format_geo_country(entry.get("geo"), short=True),
            )

    geo_stats = aggregate_geo_stats(risk_report)
    country_codes = _country_codes_from_report(risk_report)
    country_panel = render_country_chart(geo_stats, country_codes=country_codes)

    sqli_count = sum(results.get("sql_injection", {}).values()) or len(results.get("sql_injection", {}))
    scan_count = sum(results.get("scanners", {}).values()) or len(results.get("scanners", {}))
    bf_count = sum(
        1
        for _ip, n in (results.get("login_attempts") or {}).items()
        if n >= BF_THRESHOLD
    )
    attack_max = max(sqli_count, scan_count, bf_count, 1)

    attack_table = Table(title="Attack Types", expand=True)
    attack_table.add_column("Type")
    attack_table.add_column("Volume", justify="right")
    attack_table.add_column("Bar")
    for label, count, style in (
        ("SQLi", sqli_count, "red"),
        ("Scanners", scan_count, "yellow"),
        ("Brute force", bf_count, "magenta"),
    ):
        attack_table.add_row(label, str(count), Text(_bar(count, attack_max), style=style))

    title = "LogSec Monitor" if results.get("monitor_mode") else "LogSec Dashboard"
    panels = [Panel(gauges, title=title, border_style="blue")]
    if geo_stats:
        panels.append(country_panel)
    panels.extend([ip_table, attack_table])
    renderable = Group(*panels)

    if return_renderable:
        return renderable

    from rich.console import Console

    Console().print(renderable)


def build_cli_parser() -> argparse.ArgumentParser:
    examples = """
Examples:
  %(prog)s samples/access.log
  %(prog)s /var/log/apache2/access.log --threshold 25 --top 20
  %(prog)s access.log --json --no-ai
  %(prog)s access.log --pdf --email analyst@example.com
  %(prog)s access.log --monitor
  %(prog)s access.log --monitor --dashboard
  %(prog)s access.log --config config.yaml
"""
    parser = argparse.ArgumentParser(
        description="LogSec Apache access log security analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples,
    )
    parser.add_argument("log_file", help="Path to Apache/Nginx access log")
    parser.add_argument("--config", metavar="PATH", help="YAML config file (default: ./config.yaml)")
    parser.add_argument("--pdf", action="store_true", help="Generate PDF security report")
    parser.add_argument(
        "--email",
        metavar="ADDRESS",
        help="Email PDF report to ADDRESS (requires --pdf)",
    )
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        metavar="SCORE",
        help=f"Minimum risk score to show (default: {RISK_SCORE_MIN})",
    )
    parser.add_argument("--top", type=int, default=10, metavar="N", help="Top N IPs to show (default: 10)")
    parser.add_argument(
        "--bf-threshold",
        type=int,
        default=None,
        metavar="N",
        help=f"Brute-force login threshold (default: {BF_THRESHOLD})",
    )
    parser.add_argument("--login-url", default="/login", help="Login URL path for brute-force detection")
    parser.add_argument("--no-ai", action="store_true", help="Skip Claude AI analysis")
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Real-time tail mode: alert on rate/SQLi/scanner/login floods",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Rich terminal dashboard (use with --monitor for live refresh)",
    )
    parser.add_argument(
        "--geo-disable",
        action="store_true",
        help="Skip geo-IP lookups (faster, no external API)",
    )
    parser.add_argument(
        "--geo-timeout",
        type=float,
        default=None,
        metavar="SECS",
        help="Timeout in seconds for geo lookups (default: 2)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(argv)

    load_config(args.config)
    configure_geoip(
        enabled=False if args.geo_disable else None,
        timeout_seconds=args.geo_timeout,
    )

    threshold = RISK_SCORE_MIN if args.threshold is None else args.threshold
    bf_threshold = BF_THRESHOLD if args.bf_threshold is None else args.bf_threshold

    log_path = args.log_file
    if not os.path.isfile(log_path):
        print(f"Error: log file not found: {log_path}", file=sys.stderr)
        return 1

    if args.email and not args.pdf:
        parser.error("--email requires --pdf")

    if args.monitor:
        monitor_log(
            log_path,
            login_url=args.login_url,
            dashboard=args.dashboard,
        )
        return 0

    results = analyze_file(
        log_path,
        login_url=args.login_url,
        bf_threshold=bf_threshold,
        risk_score_min=threshold,
    )

    if results.get("error"):
        print_report(results)
        return 1

    if args.dashboard:
        show_dashboard(results)
    elif args.json:
        print(format_json_report(results, top=args.top))
    else:
        print_report(results, top=args.top, bf_threshold=bf_threshold, threshold=threshold)

    pdf_path = "report.pdf"
    if args.pdf:
        export_pdf_report(results, pdf_path)
    if args.email:
        send_pdf_report(pdf_path, args.email)

    risk_report = [e for e in results.get("risk_report", []) if e.get("score", 0) >= threshold]
    if risk_report and not args.no_ai and not args.json:
        print("\n--- STARTING AI SECURITY ANALYSIS ---")
        try:
            print(">> Requesting analysis from Claude...")
            ai_results = analyze_with_claude(risk_report)
            print(">> Success!\n")
            print("=== AI SECURITY REPORT ===")
            print(json.dumps(ai_results, indent=2))
        except Exception as e:
            print(f">> AI analysis failed: {e}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
