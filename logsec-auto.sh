#!/bin/bash

LOG_FILE="/var/log/apache2/access.log"
REPORT="report.pdf"
ALERT_EMAIL="jobhunteredrick@gmail.com"
TOOLKIT_DIR="$(dirname "$0")"
MIN_LEVEL="HIGH"

cd "$TOOLKIT_DIR/src"

# Run analysis
rm -f "$TOOLKIT_DIR/src/logsec/seen_ips.json"
OUTPUT=$(python3 -m logsec apache "$LOG_FILE" --no-ai --geo-disable 2>&1)

# Check if CRITICAL or HIGH threats found
if echo "$OUTPUT" | grep -qE "CRITICAL|HIGH"; then
    python3 -m logsec apache "$LOG_FILE" --pdf --email "$ALERT_EMAIL" --no-ai --geo-disable
    echo "[$(date)] Threat detected - report sent to $ALERT_EMAIL"
else
    echo "[$(date)] No threats detected"
fi
