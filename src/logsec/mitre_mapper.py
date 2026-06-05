import re
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
from pathlib import Path


class MITREMapper:
    """Maps detection patterns to MITRE ATT&CK techniques"""

    TECHNIQUES = {
        # Initial Access (TA0001)
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "tactic": "TA0001",
            "patterns": [r"'\s+OR\s+", r"UNION\s+SELECT", r"--", r";\s*DROP",
                         r"'\s*=\s*'", r"1=1", r"xp_cmdshell"],
        },
        "T1133": {
            "name": "External Remote Services",
            "tactic": "TA0001",
            "patterns": [r"/ssh", r"/rdp", r"/vnc", r"/teamviewer"],
        },

        # Execution (TA0002)
        "T1059": {
            "name": "Command and Scripting Interpreter",
            "tactic": "TA0002",
            "patterns": [r"cmd\.exe", r"powershell", r"bash", r"sh\s+-c", r"eval\("],
        },

        # Persistence (TA0003)
        "T1078": {
            "name": "Valid Accounts",
            "tactic": "TA0003",
            "patterns": ["night_activity", "first_time_ip"],
        },

        # Defense Evasion (TA0005)
        "T1006": {
            "name": "Directory Traversal",
            "tactic": "TA0005",
            "patterns": [r"\.\./", r"\.\.\\", r"/etc/passwd", r"/windows/win\.ini"],
        },
        "T1027": {
            "name": "Obfuscated Files or Info",
            "tactic": "TA0005",
            "patterns": [r"%[0-9A-F]{2}", r"base64", r"hex\(\)"],
        },

        # Credential Access (TA0006)
        "T1110.001": {
            "name": "Password Guessing",
            "tactic": "TA0006",
            "patterns": ["brute_force", "failed_logins_gt_5"],
        },

        # Discovery (TA0007)
        "T1595.002": {
            "name": "Vulnerability Scanning",
            "tactic": "TA0007",
            "patterns": [r"/wp-admin", r"/phpmyadmin", r"/\.env", r"/api/v[0-9]",
                         r"/backup", r"/config\.json", r"/\.git"],
        },
        "T1040": {
            "name": "Network Sniffing",
            "tactic": "TA0007",
            "patterns": [r"/capture", r"/sniff", r"/tcpdump"],
        },

        # Exfiltration (TA0010)
        "T1048": {
            "name": "Exfiltration Over Alternative Protocol",
            "tactic": "TA0010",
            "patterns": ["large_response"],
        },

        # Impact (TA0040)
        "T1499": {
            "name": "Endpoint Denial of Service",
            "tactic": "TA0040",
            "patterns": [r"requests_per_second_gt_100"],
        },
    }

    TACTIC_NAMES = {
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0010": "Exfiltration",
        "TA0011": "Command and Control",
        "TA0040": "Impact",
    }

    # Sentinel flag patterns — evaluated by context, not regex
    _SPECIAL_FLAGS = {
        "night_activity", "first_time_ip", "brute_force",
        "failed_logins_gt_5", "large_response", "requests_per_second_gt_100",
    }

    def __init__(self):
        self.cache = {}
        self.ip_technique_history = defaultdict(list)
        self.detection_timeline = []

    def map_request(
        self,
        request: str,
        status_code: int,
        user_agent: str,
        ip: str,
        timestamp: datetime,
        failure_count: int = 0,
        response_size: int = 0,
        requests_per_second: float = 0,
    ) -> List[Dict]:
        """Main mapping function returning matched techniques with metadata."""
        cache_key = f"{ip}_{request[:50]}_{timestamp.minute}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        matches = []
        request_lower = request.lower()
        ua_lower = user_agent.lower()

        for tech_id, tech_info in self.TECHNIQUES.items():
            for pattern in tech_info["patterns"]:
                matched = self._match_pattern(
                    pattern, request_lower, ua_lower, status_code,
                    ip, timestamp, failure_count, response_size, requests_per_second,
                )
                if matched:
                    matches.append({
                        "technique_id": tech_id,
                        "technique_name": tech_info["name"],
                        "tactic_id": tech_info["tactic"],
                        "tactic_name": self.TACTIC_NAMES.get(tech_info["tactic"], "Unknown"),
                        "pattern_matched": pattern,
                        "timestamp": timestamp.isoformat(),
                    })
                    break  # one pattern per technique is enough

        unique_matches = list({m["technique_id"]: m for m in matches}.values())

        for match in unique_matches:
            self.ip_technique_history[ip].append(match["technique_id"])
            self.detection_timeline.append({"ip": ip, "timestamp": timestamp.isoformat(), **match})

        self.cache[cache_key] = unique_matches
        return unique_matches

    def _match_pattern(
        self,
        pattern: str,
        request_lower: str,
        ua_lower: str,
        status_code: int,
        ip: str,
        timestamp: datetime,
        failure_count: int,
        response_size: int,
        requests_per_second: float,
    ) -> bool:
        """Evaluate a single pattern against the current request context."""
        if pattern not in self._SPECIAL_FLAGS:
            try:
                if re.search(pattern, request_lower, re.IGNORECASE):
                    return True
                if re.search(pattern, ua_lower, re.IGNORECASE):
                    return True
            except re.error:
                # Fall back to plain substring match for malformed patterns
                if pattern.lower() in request_lower or pattern.lower() in ua_lower:
                    return True
            return False

        # Special sentinel flags
        if pattern == "night_activity":
            return 2 <= timestamp.hour <= 5
        if pattern == "first_time_ip":
            return ip not in self.ip_technique_history
        if pattern == "brute_force":
            return failure_count >= 5
        if pattern == "failed_logins_gt_5":
            return status_code in (401, 403) and failure_count >= 5
        if pattern == "large_response":
            return response_size > 500 * 1024  # 500 KB
        if pattern == "requests_per_second_gt_100":
            return requests_per_second > 100
        return False

    def get_attack_chain(self, ip: str, timeframe_minutes: int = 60) -> List[Dict]:
        """Get sequence of techniques from the same IP within the given timeframe."""
        cutoff = datetime.now() - timedelta(minutes=timeframe_minutes)
        chain = [
            t for t in self.detection_timeline
            if t["ip"] == ip and datetime.fromisoformat(t["timestamp"]) > cutoff
        ]
        return sorted(chain, key=lambda x: x["timestamp"])

    def export_navigator_layer(self, output_path: str = "mitre_navigator_layer.json") -> str:
        """Export a MITRE ATT&CK Navigator-compatible JSON layer file."""
        technique_scores: Dict[str, int] = defaultdict(int)
        for detection in self.detection_timeline:
            technique_scores[detection["technique_id"]] += 1

        max_score = max(technique_scores.values()) if technique_scores else 1

        techniques = [
            {
                "techniqueID": tech_id,
                "score": int((count / max_score) * 100),
                "color": self._get_technique_color(tech_id),
                "comment": f"Detected {count} time{'s' if count != 1 else ''}",
            }
            for tech_id, count in technique_scores.items()
        ]

        navigator_layer = {
            "name": "LogSec Apache Analysis",
            "versions": {
                "attack": "14",
                "navigator": "4.9",
                "layer": "4.4",
            },
            "domain": "enterprise-attack",
            "description": "Automated detection from Apache logs",
            "filters": {"platforms": ["Linux", "Windows", "macOS"]},
            "sorting": 0,
            "layout": {"layout": "side", "showID": True, "showName": True},
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ff0000", "#ffff00", "#00ff00"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [],
            "metadata": [],
            "links": [],
            "selectTechniquesAcrossLayers": True,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(navigator_layer, f, indent=2)

        return output_path

    def _get_technique_color(self, tech_id: str) -> str:
        """Return a hex colour based on the tactic of the given technique."""
        tactic_colors = {
            "TA0001": "#ff9999",
            "TA0002": "#99ff99",
            "TA0003": "#9999ff",
            "TA0004": "#ffff99",
            "TA0005": "#ff99ff",
            "TA0006": "#99ffff",
            "TA0007": "#ffcc99",
            "TA0008": "#cc99ff",
            "TA0009": "#99ffcc",
            "TA0010": "#ff9999",
            "TA0011": "#99ccff",
            "TA0040": "#cc9999",
        }
        tactic = self.TECHNIQUES.get(tech_id, {}).get("tactic", "")
        return tactic_colors.get(tactic, "#cccccc")

    def get_statistics(self) -> Dict:
        """Return MITRE statistics for reporting."""
        techniques_count: Dict[str, int] = defaultdict(int)
        tactics_count: Dict[str, int] = defaultdict(int)

        for detection in self.detection_timeline:
            techniques_count[detection["technique_id"]] += 1
            tactics_count[detection["tactic_name"]] += 1

        return {
            "total_detections": len(self.detection_timeline),
            "unique_ips": len(self.ip_technique_history),
            "top_techniques": sorted(
                techniques_count.items(), key=lambda x: x[1], reverse=True
            )[:5],
            "tactics_summary": dict(tactics_count),
            "attack_chains": sum(
                1 for chain in self.ip_technique_history.values() if len(chain) > 1
            ),
        }
