# LogSec Toolkit

![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)
![CLI](https://img.shields.io/badge/interface-CLI-black)

Defensive log analysis CLI for Apache access logs and OWASP Juice Shop docker logs.
Combines rule-based threat detection with AI-powered batch analysis (Claude).

Designed for defensive security practice and log-based threat detection in lab environments.

## Features

### Core analysis

- Apache/Nginx access log parsing and analysis
- Top IP detection and traffic analysis
- 4xx / 5xx error tracking
- Brute-force login detection heuristics
- Vulnerability scanner detection (sensitive paths + suspicious User-Agents)
- Flood/DDoS pattern detection
- OWASP Juice Shop docker log parsing
- Suspicious admin login indicator detection (lab context)
- Unified risk scoring per IP (LOW / MEDIUM / HIGH / CRITICAL)
- JSON-ready structured output (`--output`)
- Command-line interface (CLI)

### Threat intelligence

- **Threat intel blocklist** — IPs listed in `samples/blocklist.txt` receive an elevated risk score and a dedicated reason in the risk report (`IP found in threat intelligence blocklist`). Edit this file to add known-malicious addresses for your environment.

### Reporting & delivery

- **Executive summary PDF** — `--pdf` generates `report.pdf` with an executive summary (flagged IP counts by severity, top priority IP) and a full risk breakdown per IP.
- **Email delivery** — `--email ADDRESS` builds the PDF and sends it via Gmail SMTP (requires `GMAIL_SENDER` and `GMAIL_APP_PASSWORD` in `.env`).

### AI analysis

- **Batch AI analysis** — All flagged IPs in the risk report are sent to Claude in a single API request. The model returns one JSON object per IP (threat classification + recommendation). Use `--no-ai` to skip.

### Alerting & response

- **Alert deduplication** — Console alerts for MEDIUM+ IPs are suppressed on repeat runs if the IP was already alerted. State is persisted in `src/logsec/seen_ips.json`. Delete or edit that file to reset deduplication.
- **Auto-block** — `--auto-block` adds an `iptables DROP` rule for each IP rated **CRITICAL** (requires `sudo`; lab use only).

### Automation

- **Cron job scheduling** — Run periodic scans against live or rotated logs (see [Scheduled runs](#scheduled-runs-cron) below).
- **Automated agent** — `logsec_agent.py` runs the full pipeline unattended: analyze → AI triage → PDF → email, triggered only when CRITICAL or HIGH threats are found (see [Automated agent](#automated-agent) below).

## Installation

Clone the repository:

```bash
git clone https://github.com/jcabangonzalez/logsec-toolkit.git
cd logsec-toolkit
```

## Setup

```bash
pip install anthropic google-genai python-dotenv requests reportlab pyyaml rich
```

Create `.env` in `src/` (or your working directory) with:

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Claude API for batch AI analysis |
| `GEMINI_API_KEY` | Optional; reserved for future fallback |
| `GMAIL_SENDER` | Sender address for `--email` |
| `GMAIL_APP_PASSWORD` | Gmail app password for `--email` |

Customize the threat intel blocklist:

```bash
# One IP per line
samples/blocklist.txt
```

## Usage

From the `logsec-toolkit` directory:

```bash
./logsec-run.sh apache samples/access.log
```

Or explicitly:

```bash
cd src
PYTHONPATH=. python3 -m logsec.cli apache ../samples/access.log
```

### Apache logs — common options

| Flag | Description |
|------|-------------|
| `--top N` | Show top N IPs (default: 10) |
| `--login-url PATH` | Login endpoint for brute-force detection (default: `/login`) |
| `--bf-threshold N` | Brute-force alert threshold (default: 3) |
| `--output FILE` | Save risk report as JSON |
| `--pdf` | Export executive summary + risk report PDF |
| `--email ADDRESS` | Generate PDF and email it |
| `--no-ai` | Skip batch Claude analysis |
| `--auto-block` | Block CRITICAL IPs via iptables |

#### Basic scan

```bash
./logsec-run.sh apache samples/access.log --top 5
```

#### PDF executive summary

```bash
./logsec-run.sh apache samples/access.log --pdf
```

#### Email report

```bash
./logsec-run.sh apache samples/access.log --email security@example.com
```

#### Full pipeline (PDF + AI + auto-block)

```bash
./logsec-run.sh apache samples/access.log --pdf --email security@example.com --auto-block
```

#### JSON export without AI

```bash
./logsec-run.sh apache samples/access.log --output report.json --no-ai
```

### OWASP Juice Shop logs

```bash
./logsec-run.sh juice samples/juice_shop_docker.log --top 10
```

### What Apache analysis detects

- Top IP addresses by request volume
- HTTP 4xx/5xx error statistics
- Brute-force login attempts (POST to login URL)
- Scanner probes against sensitive paths (`/.env`, `/wp-admin`, etc.)
- Suspicious User-Agents (sqlmap, nikto, nmap, …)
- Request-rate floods and off-hours activity
- Blocklist matches from threat intelligence feed

### Alert deduplication (`seen_ips.json`)

On each run, IPs that already triggered a console alert are skipped. New alerts are appended to `src/logsec/seen_ips.json`. This avoids duplicate noise when the same log file or recurring traffic is analyzed on a schedule.

To alert again on a previously seen IP, remove that IP from `seen_ips.json` or delete the file.

### Scheduled runs (cron)

Example: analyze yesterday’s Apache log every day at 06:00, email the PDF, and rely on deduplication for repeat offenders:

```cron
0 6 * * * cd /path/to/logsec-toolkit && ./logsec-run.sh apache /var/log/apache2/access.log.1 --pdf --email you@example.com >> /var/log/logsec-cron.log 2>&1
```

Example: hourly scan with JSON output (no email):

```cron
0 * * * * cd /path/to/logsec-toolkit && ./logsec-run.sh apache /var/log/apache2/access.log --output /tmp/logsec-report.json --no-ai
```

Ensure the cron user has read access to log files, valid `.env` API keys, and (if using `--auto-block`) passwordless `sudo` for `iptables` — only in controlled lab environments.

### Automated agent

`logsec_agent.py` runs the full detection-to-delivery pipeline without any flags. It is designed to be invoked directly or from a cron job.

**Pipeline:**

1. Parses `samples/access.log` with the same rule engine as the CLI
2. Checks whether any flagged IP scored **CRITICAL** or **HIGH**
3. If no such threats exist, exits cleanly with no side effects
4. If threats are found: sends the risk report to Claude for per-IP triage, exports a PDF, and emails it to the configured recipient

**Outputs:**

| Output | Path |
|--------|------|
| Structured log | `logsec_agent.log` (project root) |
| PDF report | `logsec_agent_report.pdf` (project root) |
| Email recipient | `jobhunteredrick@gmail.com` |

**Run:**

```bash
python3 logsec_agent.py
```

**Sample output (threats detected):**

```
2026-06-05 09:43:18 [INFO] LogSec agent starting
2026-06-05 09:43:18 [INFO] Target log: .../samples/access.log
2026-06-05 09:43:18 [INFO] Analysis complete: 37 total requests, 2 flagged IP(s)
2026-06-05 09:43:18 [INFO] Threat levels requiring action — CRITICAL: 1, HIGH: 1
2026-06-05 09:43:18 [INFO] Requesting AI triage for 2 IP(s)
2026-06-05 09:43:21 [INFO] AI triage complete: 2 IP(s) assessed
2026-06-05 09:43:21 [INFO]   [CRITICAL] 1.2.3.4 — Immediately block IP at firewall and WAF.
2026-06-05 09:43:21 [INFO]   [HIGH] 5.5.5.5 — Implement rate limiting and monitor for escalation.
2026-06-05 09:43:21 [INFO] PDF export successful
2026-06-05 09:43:22 [INFO] Email delivered to jobhunteredrick@gmail.com
2026-06-05 09:43:22 [INFO] LogSec agent completed successfully
```

**Cron example** — run every night at 02:00:

```cron
0 2 * * * cd /path/to/logsec-toolkit && python3 logsec_agent.py >> /var/log/logsec_agent.log 2>&1
```

Requires `ANTHROPIC_API_KEY`, `GMAIL_SENDER`, and `GMAIL_APP_PASSWORD` in `.env`.

### Example JSON output

```json
[
  {
    "ip": "192.168.1.10",
    "risk_level": "CRITICAL",
    "score": 85,
    "reasons": [
      "IP found in threat intelligence blocklist: 192.168.1.10",
      "Likely brute force: 12 attempts"
    ]
  }
]
```

## Stack

- Python 3.10+
- Anthropic Claude API (`claude-haiku-4-5`)
- ReportLab (PDF reports)
- argparse, collections, re, dotenv, smtplib
