import re
from collections import Counter

# Ejemplo:
# Error: Blocked illegal activity by ::ffff:172.17.0.1
BLOCKED_RE = re.compile(r"Blocked illegal activity by (?P<ip>\S+)")

# Ejemplo:
# info: Solved 2-star loginAdminChallenge (Login Admin)
SOLVED_RE = re.compile(r"Solved .* (?P<challenge>\w+)\s*\((?P<label>[^)]+)\)")

def analyze_juice_logs(filepath: str):
    blocked_by_ip = Counter()
    solved_challenges = Counter()
    blocked_total = 0
    solved_total = 0

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = BLOCKED_RE.search(line)
                if m:
                    blocked_total += 1
                    blocked_by_ip[m.group("ip")] += 1
                    continue

                m = SOLVED_RE.search(line)
                if m:
                    solved_total += 1
                    key = f"{m.group('challenge')} ({m.group('label')})"
                    solved_challenges[key] += 1
                    continue

    except FileNotFoundError:
        return {"error": "not_found", "filepath": filepath}
    except PermissionError:
        return {"error": "permission", "filepath": filepath}
    except Exception as e:
        return {"error": f"unexpected: {e}", "filepath": filepath}

    return {
        "error": None,
        "filepath": filepath,
        "blocked_total": blocked_total,
        "solved_total": solved_total,
        "blocked_by_ip": blocked_by_ip,
        "solved_challenges": solved_challenges,
    }

def print_juice_report(results, top: int = 10):
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
    print(f"Blocked illegal activity (total): {results['blocked_total']}")
    print(f"Solved challenges (total): {results['solved_total']}")

    if results["blocked_by_ip"]:
        print(f"\nTop {top} IPs con 'Blocked illegal activity':")
        for ip, count in results["blocked_by_ip"].most_common(top):
            print(ip, count)

    if results["solved_challenges"]:
        print(f"\nChallenges resueltos detectados:")
        for ch, count in results["solved_challenges"].most_common(top):
            print(ch, count)