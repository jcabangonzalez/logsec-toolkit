import argparse
import os 

from logsec.apache_analyzer import (
    analyze_file as analyze_apache_file,
    analyze_with_claude,
    export_pdf_report,
    print_report as print_apache_report,
)
from logsec.juice_analyzer import analyze_juice_logs, print_juice_report


def build_parser():
    p = argparse.ArgumentParser(description="LogSec Toolkit (Apache + Juice Shop log detection)")
    sub = p.add_subparsers(dest="command", required=True)

    ap = sub.add_parser("apache", help="Analyze Apache/Nginx access logs")
    ap.add_argument("logfile", help="Path to access.log")
    ap.add_argument("--top", type=int, default=10, help="Top N IPs (default: 10)")
    ap.add_argument("--login-url", default="/login", help="Login URL to track (default: /login)")
    ap.add_argument("--bf-threshold", type=int, default=3, help="Brute-force threshold (default: 3)")
    ap.add_argument("--output", help="Save risk report as JSON file (e.g. report.json)")
    ap.add_argument("--no-ai", action="store_true", help="Skip AI analysis and show risk report only")
    ap.add_argument("--pdf", action="store_true", help="Export risk report as PDF file")
    ap.add_argument("--auto-block", action="store_true", help="Auto-block CRITICAL IPs using iptables")

    js = sub.add_parser("juice", help="Analyze OWASP Juice Shop docker logs")
    js.add_argument("logfile", help="Path to juice_shop_docker.log")
    js.add_argument("--top", type=int, default=10, help="Top N (default: 10)")

    return p


def main():
    args = build_parser().parse_args()

    if args.command == "apache":
        results = analyze_apache_file(args.logfile, login_url=args.login_url)
        print_apache_report(results, top=args.top, bf_threshold=args.bf_threshold)
        export_pdf_report(results)

        if args.output and results.get("risk_report"):
            import json
            with open(args.output, "w") as f:
                json.dump(results["risk_report"], f, indent=2)
            print(f"\n[+] Risk report saved to {args.output}")

        if results.get("risk_report") and not args.no_ai:
            import json

            print("\n--- STARTING AI SECURITY ANALYSIS ---")
            try:
                print(">> Requesting analysis from Claude...")
                ai_results = analyze_with_claude(results["risk_report"])
                print(">> Success!\n")
                print("=== AI SECURITY REPORT ===")
                print(json.dumps(ai_results, indent=2))
            except Exception as e:
                print(f">> AI analysis failed: {e}")
    if args.auto_block:
        for entry in results["risk_report"]:
            if entry["risk_level"] == "CRITICAL":
                ip = entry["ip"]
                os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
                print(f"[BLOCKED] {ip}")   
        return

    if args.command == "juice":
        results = analyze_juice_logs(args.logfile)
        print_juice_report(results, top=args.top)
        return


if __name__ == "__main__":
    main()
