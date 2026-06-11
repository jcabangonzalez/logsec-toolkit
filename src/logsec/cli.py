import argparse
import os
import json
import sys

from logsec.apache_analyzer import (
    analyze_file as analyze_apache_file,
    analyze_with_claude,
    configure_geoip,
    export_pdf_report,
    format_json_report,
    load_config,
    monitor_log,
    print_report as print_apache_report,
    send_pdf_report,
    show_dashboard,
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
    ap.add_argument("--email", metavar="ADDRESS", help="Email PDF report to this address (requires --pdf)")
    ap.add_argument("--json", action="store_true", help="JSON output instead of text report")
    ap.add_argument("--threshold", type=int, default=None, metavar="SCORE", help="Minimum risk score to show")
    ap.add_argument("--config", metavar="PATH", help="YAML config file path")
    ap.add_argument("--monitor", action="store_true", help="Real-time tail monitoring mode")
    ap.add_argument("--dashboard", action="store_true", help="Rich terminal dashboard")
    ap.add_argument("--auto-block", action="store_true", help="Auto-block CRITICAL IPs using iptables")
    ap.add_argument("--geo-disable", action="store_true", help="Skip geo-IP lookups (faster, no external API)")
    ap.add_argument("--geo-timeout", type=float, default=None, metavar="SECS", help="Timeout for geo lookups")
    ap.add_argument("--mitre", action="store_true", help="Show MITRE ATT&CK techniques")
    ap.add_argument("--mitre-export", action="store_true", help="Export MITRE ATT&CK Navigator layer to JSON")
    ap.add_argument("--ollama", action="store_true", help="Use local Ollama (Qwen) for AI triage")
    ap.add_argument("--ollama-model", default="qwen2.5-coder:latest", metavar="MODEL", help="Ollama model to use")
    ap.add_argument("--include-internal", action="store_true", help="Include RFC1918/local IPs (skipped by default)")
    ap.add_argument("--jsonl", action="store_true", help="Export results as JSON Lines (one JSON per line)")

    js = sub.add_parser("juice", help="Analyze OWASP Juice Shop docker logs")
    js.add_argument("logfile", help="Path to juice_shop_docker.log")
    js.add_argument("--top", type=int, default=10, help="Top N (default: 10)")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "apache":
        load_config(getattr(args, "config", None))
        configure_geoip(
            enabled=False if args.geo_disable else None,
            timeout_seconds=args.geo_timeout,
        )
        if args.email and not args.pdf:
            parser.error("apache: --email requires --pdf")

        if args.monitor:
            monitor_log(
                args.logfile,
                login_url=args.login_url,
                dashboard=args.dashboard,
            )
            return 0

        threshold = args.threshold
        results = analyze_apache_file(
            args.logfile,
            login_url=args.login_url,
            bf_threshold=args.bf_threshold,
            risk_score_min=threshold,
            mitre=args.mitre,
            ollama=args.ollama,
        )

        # JSONL export
        if args.jsonl:
            risk_entries = results.get('risk_report', [])
            lines = []
            for entry in risk_entries:
                json_line = {
                    "ip": entry.get("ip"),
                    "risk_level": entry.get("risk_level"),
                    "risk_score": entry.get("score"),
                    "reasons": entry.get("reasons", [])
                }
                lines.append(json.dumps(json_line))
            print('\n'.join(lines))
            return 0

        if results.get("error"):
            print_apache_report(results)
            return 1

        if args.dashboard:
            show_dashboard(results)
        elif args.json:
            print(format_json_report(results, top=args.top))
        else:
            print_apache_report(
                results,
                top=args.top,
                bf_threshold=args.bf_threshold,
                threshold=threshold,
            )

        pdf_path = "report.pdf"
        if args.pdf:
            export_pdf_report(results, pdf_path)
        if args.email:
            send_pdf_report(pdf_path, args.email)

        if args.output and results.get("risk_report"):
            with open(args.output, "w") as f:
                json.dump(results["risk_report"], f, indent=2)
            print(f"\n[+] Risk report saved to {args.output}")

        risk_report = results.get("risk_report") or []
        if risk_report and not args.no_ai and not args.json:
            print("\n--- STARTING AI SECURITY ANALYSIS ---")
            try:
                print(">> Requesting analysis from Claude...")
                ai_results = analyze_with_claude(risk_report)
                print(">> Success!\n")
                print("=== AI SECURITY REPORT ===")
                print(json.dumps(ai_results, indent=2))
            except Exception as e:
                print(f">> AI analysis failed: {e}")

        if args.auto_block:
            for entry in results.get("risk_report", []):
                if entry["risk_level"] == "CRITICAL":
                    ip = entry["ip"]
                    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
                    print(f"[BLOCKED] {ip}")
        return 0

    if args.command == "juice":
        results = analyze_juice_logs(args.logfile)
        print_juice_report(results, top=args.top)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
