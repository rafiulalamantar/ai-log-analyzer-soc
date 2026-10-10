#!/usr/bin/env bash
# Send a sample log file to a running API and pretty-print the assessment.
# Usage: scripts/smoke.sh [data/samples/auth_brute_force.log]
set -euo pipefail

FILE="${1:-data/samples/auth_brute_force.log}"
API="${API:-http://localhost:8000}"

python3 -c "
import json, sys, urllib.request
log = open('$FILE').read()
req = urllib.request.Request(
    '$API/analyze',
    data=json.dumps({'log': log, 'source': '$(basename "$FILE")'}).encode(),
    headers={'Content-Type': 'application/json'},
)
print(json.dumps(json.load(urllib.request.urlopen(req, timeout=180)), indent=2))
"
