# LogSec Toolkit

Lightweight defensive log analysis toolkit for Apache access logs and OWASP Juice Shop docker logs.

---

## Features

- Apache/Nginx access log analysis
- Top IP detection
- 4xx / 5xx error tracking
- Brute-force login heuristic detection
- OWASP Juice Shop docker log analysis
- Detection of solved security challenges (lab indicators)
- JSON report export (`--out`)

---

## Usage

### Apache logs

```bash
PYTHONPATH=src python3 -m logsec.cli apache samples/access.log --top 5
PYTHONPATH=src python3 -m logsec.cli apache samples/access.log --top 5 --out reports/apache_report.jsonPYTHONPATH=src python3 -m logsec.cli juice samples/juice_shop_docker.log --top 10PYTHONPATH=src python3 -m logsec.cli juice samples/juice_shop_docker.log --top 10 --out reports/juice_report.json
