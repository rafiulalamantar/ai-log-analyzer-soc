#!/usr/bin/env bash
# Import the triage workflow, publish it, and start n8n.
# Usage: n8n/start.sh        (run from anywhere; the API must be running separately)
#
# Webhook: POST http://localhost:5678/webhook/soc-triage  {"log": "...", "source": "auth.log"}
# Output:  data/incidents/incidents.jsonl (every log) and alerts.jsonl (high/critical)
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p data/incidents

# n8n only reads and writes files under this directory.
export N8N_RESTRICT_FILE_ACCESS_TO="$PWD/data/incidents"
export N8N_DIAGNOSTICS_ENABLED=false
export N8N_PERSONALIZATION_ENABLED=false

n8n import:workflow --input=n8n/soc_triage.json
n8n publish:workflow --id=socTriage0000001
exec n8n start
