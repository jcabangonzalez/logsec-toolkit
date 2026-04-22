import argparse

from logsec.apache_analyzer import analyze_file as analyze_apache_file, print_report as print_apache_report
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

    js = sub.add_parser("juice", help="Analyze OWASP Juice Shop docker logs")
    js.add_argument("logfile", help="Path to juice_shop_docker.log")
    js.add_argument("--top", type=int, default=10, help="Top N (default: 10)")

    return p


def main():
    args = build_parser().parse_args()

    if args.command == "apache":
        results = analyze_apache_file(args.logfile, login_url=args.login_url)
        print_apache_report(results, top=args.top, bf_threshold=args.bf_threshold)

        if args.output and results.get("risk_report"):
            import json
            with open(args.output, "w") as f:
                json.dump(results["risk_report"], f, indent=2)
            print(f"\n[+] Risk report saved to {args.output}")

        if results.get("risk_report") and not args.no_ai:
            import json, os
            from dotenv import load_dotenv
            from anthropic import Anthropic
            from google import genai

            load_dotenv()
            print("\n--- STARTING AI SECURITY ANALYSIS ---")
            report_text = json.dumps(results["risk_report"], indent=2)

            try:
                print(">> Requesting analysis from Anthropic...")
                client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
                response = client.messages.create(
                    model="claude-haiku-4-5-20251001",
                    max_tokens=1000,
                    messages=[{"role": "user", "content": f"Analyze these IPs and tell me who to block: {report_text}"}]
                )
                print(">> Success with Anthropic!\n")
                print("=== AI SECURITY REPORT ===")
                print(response.content[0].text)

            except Exception as e:
                print(f">> Anthropic failed: {e}")
                print(">> Connecting to Gemini...")
                gemini = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
                response = gemini.models.generate_content(
                    model="gemini-2.0-flash",
                    contents=f"Analyze these IPs and tell me who to block: {report_text}"
                )
                print(">> Success with Gemini!\n")
                print("=== AI SECURITY REPORT ===")
                print(response.text)
        return

    if args.command == "juice":
        results = analyze_juice_logs(args.logfile)
        print_juice_report(results, top=args.top)
        return


if __name__ == "__main__":
    main()
