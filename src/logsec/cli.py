import argparse
import json
from pathlib import Path

from logsec.apache_analyzer import analyze_file as analyze_apache_file, print_report as print_apache_report
from logsec.juice_analyzer import analyze_juice_logs, print_juice_report


def write_json(path: str, obj: dict):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def build_parser():
    p = argparse.ArgumentParser(description="LogSec Toolkit")
    sub = p.add_subparsers(dest="command", required=True)

    ap = sub.add_parser("apache", help="Analyze Apache/Nginx access logs")
    ap.add_argument("logfile")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--login-url", default="/login")
    ap.add_argument("--bf-threshold", type=int, default=3)
    ap.add_argument("--out", default=None, help="Write JSON report to file")

    js = sub.add_parser("juice", help="Analyze OWASP Juice Shop docker logs")
    js.add_argument("logfile")
    js.add_argument("--top", type=int, default=10)
    js.add_argument("--out", default=None, help="Write JSON report to file")

    return p


def main():
    args = build_parser().parse_args()

    if args.command == "apache":
        results = analyze_apache_file(args.logfile, login_url=args.login_url)
        print_apache_report(results, top=args.top, bf_threshold=args.bf_threshold)
        if args.out:
            write_json(args.out, results)
        return

    if args.command == "juice":
        results = analyze_juice_logs(args.logfile)
        print_juice_report(results, top=args.top)
        if args.out:
            write_json(args.out, results)
        return


if __name__ == "__main__":
    main()

