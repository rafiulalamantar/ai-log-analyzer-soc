"""Ship log files to the n8n triage workflow, one request per file.

    .venv/bin/python scripts/ship_logs.py data/holdout/*.log

Stands in for a log collector. Requests are sent one at a time because the
workflow replies only once the model has finished (~15 s), which keeps the
model from being flooded.
"""
import argparse
import sys
import time
from pathlib import Path

import httpx

WEBHOOK = "http://localhost:5678/webhook/soc-triage"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--url", default=WEBHOOK)
    args = ap.parse_args()

    failed = 0
    with httpx.Client(timeout=240.0) as client:
        for path in args.files:
            started = time.monotonic()
            try:
                r = client.post(args.url, json={"log": path.read_text(), "source": path.name})
                body = r.json()
            except (httpx.HTTPError, ValueError) as exc:
                print(f"{path.name:32} FAILED  {exc}")
                failed += 1
                continue
            took = time.monotonic() - started
            if r.status_code != 200:
                print(f"{path.name:32} HTTP {r.status_code}  {body}")
                failed += 1
                continue
            print(f"{path.name:32} {body['route']:7} {body.get('verdict') or '-':11} "
                  f"{body.get('severity') or '-':9} {body.get('technique_id') or '-':10} {took:5.1f}s")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
