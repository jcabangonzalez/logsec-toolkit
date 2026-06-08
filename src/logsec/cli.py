import argparse
import os 

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
    ap.add_argument(
        "--geo-disable",
        action="store_true",
        help="Skip geo-IP lookups (faster, no external API)",
    )
    ap.add_argument(
        "--geo-timeout",
        type=float,
        default=None,
        metavar="SECS",
        help="Timeout in seconds for geo lookups (default: 2)",
    )
    ap.add_argument('--mitre', action='store_true', help='Show MITRE ATT&CK techniques')
    ap.add_argument('--mitre-export', action='store_true', help='Export MITRE ATT&CK Navigator layer to JSON')
    ap.add_argument('--ollama', action='store_true', help='Use Ollama AI triage')

    js = sub.add_parser("juice", help="Analyze OWASP Juice Shop docker logs")
    js.add_argument("logfile", help="Path to juice_shop_docker.log")
    js.add_argument("--top", type=int, default=10, help="Top N (default: 10)")

    return p


def main():
    args = build_parser().parse_args()

    if args.command == "apache":
        load_config(getattr(args, "config", None))
        configure_geoip(
            enabled=False if args.geo_disable else None,
            timeout_seconds=args.geo_timeout,
        )
        if args.email and not args.pdf:
            build_parser().error("apache: --email requires --pdf")

        if args.monitor:
            monitor_log(
                args.logfile,
                login_url=args.login_url,
                dashboard=args.dashboard,
            )
            return

        threshold = args.threshold
        results = analyze_apache_file(
            args.logfile,
            login_url=args.login_url,
            bf_threshold=args.bf_threshold,
            risk_score_min=threshold,
            ollama=args.ollama,
        )

        if results.get("error"):
            print_apache_report(results)
            return

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
        if args.mitre:
            print("\n=== MITRE ATT&CK TECHNIQUES ===")
            for ip, profile in results.get("ip_profiles", {}).items():
                mitre = profile.get("mitre", [])
                if mitre:
                    unique = list({m["technique_id"]: m for m in mitre}.values())
                    print(f"\n{ip}:")
                    for t in unique:
                        print(f"  [{t['technique_id']}] {t['technique_name']} ({t['tactic_name']})")

        if args.mitre_export:
            layer_path = "mitre_navigator_layer.json"
            results["mitre_mapper"].export_navigator_layer(layer_path)
            print(f"\n[+] MITRE ATT&CK Navigator layer saved to {layer_path}")

        if args.ollama:
            print("\n=== OLLAMA AI TRIAGE ===")
            for entry in results.get("risk_report", []):
                triage = entry.get("ollama_triage")
                if not triage:
                    continue
                print(f"\n{entry['ip']}:")
                if isinstance(triage, dict) and "error" not in triage and "raw" not in triage:
                    print(f"  Risk:    {triage.get('risk', '—')}")
                    print(f"  Action:  {triage.get('action', '—')}")
                    print(f"  Summary: {triage.get('summary', '—')}")
                else:
                    print(f"  {triage.get('raw') or triage.get('error') or triage}")

        pdf_path = "report.pdf"
        if args.pdf:
            export_pdf_report(results, pdf_path)
        if args.email:
            send_pdf_report(pdf_path, args.email)

        if args.output and results.get("risk_report"):
            import json
            with open(args.output, "w") as f:
                json.dump(results["risk_report"], f, indent=2)
            print(f"\n[+] Risk report saved to {args.output}")

        risk_report = results.get("risk_report") or []
        if risk_report and not args.no_ai and not args.json:
            import json

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
        return

    if args.command == "juice":
        results = analyze_juice_logs(args.logfile)
        print_juice_report(results, top=args.top)
        return


if __name__ == "__main__":
    main()
