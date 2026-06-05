import json
import logging
import sys
from pathlib import Path

# Resolve paths relative to this file so the agent works from any cwd.
_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT / "src"))

from logsec.apache_analyzer import (
    analyze_file,
    analyze_with_claude,
    export_pdf_report,
    send_pdf_report,
)

_LOG_PATH = _ROOT / "logsec_agent.log"
_SAMPLE_LOG = str(_ROOT / "samples" / "access.log")
_PDF_PATH = str(_ROOT / "logsec_agent_report.pdf")
_RECIPIENT = "jobhunteredrick@gmail.com"
_ALERT_LEVELS = {"CRITICAL", "HIGH"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(_LOG_PATH),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(__name__)


def main() -> int:
    log.info("LogSec agent starting")
    log.info(f"Target log: {_SAMPLE_LOG}")

    results = analyze_file(_SAMPLE_LOG)

    if results.get("error"):
        log.error(f"Analysis failed — {results['error']} ({results.get('filepath')})")
        return 1

    total = results.get("total_requests", 0)
    risk_report = results.get("risk_report", [])
    log.info(f"Analysis complete: {total} total requests, {len(risk_report)} flagged IP(s)")

    critical_high = [e for e in risk_report if e.get("risk_level") in _ALERT_LEVELS]

    if not critical_high:
        log.info("No CRITICAL or HIGH threats detected — skipping AI triage and email delivery")
        return 0

    level_summary = ", ".join(
        f"{lvl}: {sum(1 for e in critical_high if e['risk_level'] == lvl)}"
        for lvl in ("CRITICAL", "HIGH")
        if any(e["risk_level"] == lvl for e in critical_high)
    )
    log.info(f"Threat levels requiring action — {level_summary}")

    log.info(f"Requesting AI triage for {len(critical_high)} IP(s)")
    try:
        ai_results = analyze_with_claude(critical_high)
        log.info(f"AI triage complete: {len(ai_results)} IP(s) assessed")
        for entry in ai_results:
            log.info(
                f"  [{entry.get('risk_level', '?')}] {entry.get('ip')} — "
                f"{entry.get('recommendation', 'no recommendation')}"
            )
    except Exception as exc:
        log.error(f"AI triage failed: {exc}")

    log.info(f"Exporting PDF report to {_PDF_PATH}")
    try:
        export_pdf_report(results, _PDF_PATH)
        log.info("PDF export successful")
    except Exception as exc:
        log.error(f"PDF export failed: {exc}")
        return 1

    log.info(f"Sending PDF report to {_RECIPIENT}")
    try:
        send_pdf_report(_PDF_PATH, _RECIPIENT)
        log.info(f"Email delivered to {_RECIPIENT}")
    except Exception as exc:
        log.error(f"Email delivery failed: {exc}")
        return 1

    log.info("LogSec agent completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
