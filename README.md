# LogSec Toolkit

![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)
![CLI](https://img.shields.io/badge/interface-CLI-black)

Lightweight defensive log analysis toolkit for Apache access logs and OWASP Juice Shop docker logs.
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
