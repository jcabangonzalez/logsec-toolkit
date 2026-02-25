import re
from collections import Counter

log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\d+|-)'
)

def parse_line(line: str):
    match = log_pattern.match(line)
    if not match:
        return None
    data = match.groupdict()
    data["status"] = int(data["status"])
    data["size"] = 0 if data["size"] == "-" else int(data["size"])
    return data

def analyze_file(filepath: str, login_url: str = "/login"):
    ips = Counter()
    login_attempts = Counter()
    errors_4xx = 0
    errors_5xx = 0
    total_requests = 0
    parsed_lines = 0

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                parsed = parse_line(line)
                if not parsed:
                    continue

                parsed_lines += 1
                total_requests += 1
                ips[parsed["ip"]] += 1

                if parsed["method"] == "POST" and parsed["url"] == login_url:
                    login_attempts[parsed["ip"]] += 1

                if 400 <= parsed["status"] < 500:
                    errors_4xx += 1
                elif 500 <= parsed["status"] < 600:
                    errors_5xx += 1

    except FileNotFoundError:
        return {"error": "not_found", "filepath": filepath}
    except PermissionError:
        return {"error": "permission", "filepath": filepath}
    except Exception as e:
        return {"error": f"unexpected: {e}", "filepath": filepath}

    return {
        "error": None,
        "filepath": filepath,
        "total_requests": total_requests,
        "parsed_lines": parsed_lines,
        "errors_4xx": errors_4xx,
        "errors_5xx": errors_5xx,
        "ips": ips,
        "login_attempts": login_attempts,
    }

def print_report(results, top: int = 10, bf_threshold: int = 3):
    if results.get("error"):
        err = results["error"]
        path = results.get("filepath")
        if err == "not_found":
            print(f"Error: archivo no encontrado: {path}")
        elif err == "permission":
            print(f"Error: sin permisos para leer: {path}")
        else:
            print(f"Error: {err}")
        return

    print(f"\nArchivo: {results['filepath']}")
    print(f"Total requests: {results['total_requests']}")
    print(f"Líneas parseadas: {results['parsed_lines']}")
    print(f"Errores 4xx: {results['errors_4xx']}")
    print(f"Errores 5xx: {results['errors_5xx']}")

    print(f"\nTop {top} IPs:")
    for ip, count in results["ips"].most_common(top):
        print(ip, count)

    suspects = [(ip, n) for ip, n in results["login_attempts"].items() if n > bf_threshold]
    if suspects:
        print(f"\nPossible brute force (>{bf_threshold} intentos):")
        for ip, n in sorted(suspects, key=lambda x: x[1], reverse=True):
            print(ip, n)