# LogSec Toolkit

![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)
![CLI](https://img.shields.io/badge/interface-CLI-black)

Designed for defensive security practice and log-based threat detection in lab environments.
## Features

- Apache/Nginx access log analysis
- Brute-force login detection heuristics
- OWASP Juice Shop docker log parsing
- Suspicious admin login indicator detection (lab context)
- JSON-ready structured output
- Command-line interface (CLI)
## Installation

Clone the repository:

```bash
git clone https://github.com/jcabangonzalez/logsec-toolkit.git
cd logsec-toolkit
```
## Usage

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
