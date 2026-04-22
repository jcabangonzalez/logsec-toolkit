#!/bin/bash
cd "$(dirname "$0")/src"
python3 -m logsec.cli "$@"
