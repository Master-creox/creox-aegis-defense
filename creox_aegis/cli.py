"""Creox Aegis CLI — analyse lab/sample logs, print incidents + timeline.

Usage:
    python -m creox_aegis.cli sample_logs/auth.log sample_logs/web.log
    python -m creox_aegis.cli sample_logs/ --json report.json

No network access, no real scanning. Input is only the log files given.
"""
import argparse
import glob
import json
import os
import sys

from .correlation import correlate
from .detectors import run_detectors
from .parser import parse_file


def collect(paths: list[str]) -> list:
    events = []
    files: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "*.log"))))
        else:
            files.extend(sorted(glob.glob(p)))
    for f in files:
        events.extend(parse_file(f))
    return events


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Creox Aegis — defensive log analysis (lab only)")
    ap.add_argument("paths", nargs="+", help="Log files or directories")
    ap.add_argument("--json", dest="json_out", default=None, help="Write JSON report here")
    args = ap.parse_args(argv)
    events = collect(args.paths)
    incidents = correlate(run_detectors(events))
    print(f"Events parsed: {len(events)}")
    print(f"Incidents: {len(incidents)}")
    for inc in incidents:
        print(f"\n[{inc.risk}/100] {inc.ip}  {inc.first_ts} -> {inc.last_ts}")
        print(f"  Detectors: {', '.join(inc.detectors)}")
        for r in inc.reasons:
            print(f"  - {r}")
        print(f"  {inc.suggested_response}")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump([i.to_dict() for i in incidents], f, indent=2)
        print(f"\nJSON report written: {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
