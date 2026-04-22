# LogSec Toolkit

![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)
![CLI](https://img.shields.io/badge/interface-CLI-black)

Defensive log analysis CLI for Apache access logs and OWASP Juice Shop docker logs.
Combines rule-based threat detection with AI-powered analysis (Claude + Gemini fallback).

Designed for defensive security practice and log-based threat detection in lab environments.

## Features

- Apache/Nginx access log parsing and analysis
- Top IP detection and traffic analysis
- 4xx / 5xx error tracking
- Brute-force login detection heuristics
- Vulnerability scanner detection
- Flood/DDoS pattern detection
- OWASP Juice Shop docker log parsing
- Suspicious admin login indicator detection (lab context)
- Unified risk scoring per IP (LOW / MEDIUM / HIGH / CRITICAL)
- AI-powered security report via Claude API (Gemini fallback)
- JSON-ready structured output
- Command-line interface (CLI)

## Installation

Clone the repository:

```bash
git clone https://github.com/jcabangonzalez/logsec-toolkit.git
cd logsec-toolkit
```

## Setup

```bash
pip install anthropic google-genai python-dotenv requests
```

Create `.env` with `ANTHROPIC_API_KEY` and `GEMINI_API_KEY`.

## Usage

PYTHONPATH=logsec-toolkit/src python3 -m logsec apache logsec-toolkit/samples/access.log

### Apache Log Security Analyzer

Analyze Apache access logs and detect suspicious activity.

#### Run the analyzer

```bash
python3 analyzer.py access.log
```

#### What it detects

* Top IP addresses by request volume
* HTTP error statistics
* Possible brute-force login attempts
* Suspicious high-frequency IP activity

### Apache logs

```bash
PYTHONPATH=src python3 -m logsec.cli apache samples/access.log --top 5
```

### OWASP Juice Shop logs

```bash
PYTHONPATH=src python3 -m logsec.cli juice samples/juice_shop_docker.log --top 10
```

### Example JSON Output

```json
{
  "summary": {
    "total_requests": 10,
    "errors_4xx": 0,
    "errors_5xx": 0
  },
  "top_ips": [
    {"ip": "127.0.0.1", "count": 5},
    {"ip": "192.168.1.10", "count": 5}
  ],
  "alerts": [
    {
      "type": "brute_force",
      "endpoint": "/login",
      "ip": "192.168.1.10",
      "attempts": 5
    }
  ]
}
```

## Stack

- Python 3.10+
- Anthropic Claude API (claude-haiku-4-5)
- Google Gemini API (fallback)
- argparse, collections, re, dotenv
