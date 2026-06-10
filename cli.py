import argparse
import jsonlines
from src.logsec.apache_analyzer import analyze_file

def build_parser():
    parser = argparse.ArgumentParser(description="Apache Log Security Analyzer")
    subparsers = parser.add_subparsers(dest="command")

    # Existing commands...
    
    return parser

@safe_execute
def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        results = analyze_file(
            filepath=args.filepath,
            login_url=args.login_url,
            bf_threshold=args.bf_threshold,
            flood_threshold=args.flood_threshold,
            burst_threshold=args.burst_threshold,
            risk_score_min=args.risk_score_min,
            mitre=args.mitre,
            include_internal=args.include_internal,
        )

        if args.jsonl:
            with jsonlines.open("outputs/results.jsonl", mode='w') as writer:
                for result in results:
                    writer.write(result)

    return 0

if __name__ == '__main__':
    sys.exit(main())
