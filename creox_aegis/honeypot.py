"""Simulated honeypot lab — Phase 2.

IMPORTANT SAFETY NOTE: This is a SIMULATION only. It opens NO network
port, listens on NOTHING, and is never exposed to the real internet.
It writes fictional attacker interaction lines (in the same log format
as the v1 parser) to a file, so the v1 detectors + correlation can
analyse a honeypot incident end-to-end, safely, offline.

Usage:
    python -m creox_aegis.honeypot --out sample_logs/honeypot.log
    python -m creox_aegis.cli sample_logs/honeypot.log
"""
import argparse
import sys

ATTACKER_IP = "10.99.99.99"  # Fictional, documentation-range-style lab IP


def simulate(out_path: str) -> list[str]:
    """Write one fictional honeypot attack session. Returns the lines."""
    lines = []
    base = "2026-10-28T11:"
    # Phase A: reconnaissance — port probes
    for i, port in enumerate([22, 80, 443, 21, 3306, 8080, 53, 110, 143, 993, 995, 23]):
        lines.append(f"{base}0{i % 10}:00Z {ATTACKER_IP} PORT_PROBE port={port}")
    # Phase B: brute force against the fake login
    for i in range(6):
        lines.append(f"{base}1{i}:00Z {ATTACKER_IP} FAILED_LOGIN user=admin")
    # Phase C: web probe against the fake service
    lines.append(f"{base}20:00Z {ATTACKER_IP} WEB_REQUEST path=/login?id=1' OR '1'='1")
    lines.append(f"{base}21:00Z {ATTACKER_IP} WEB_REQUEST path=/admin")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return lines


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Creox Aegis simulated honeypot (no network, lab only)")
    ap.add_argument("--out", default="sample_logs/honeypot.log")
    args = ap.parse_args(argv)
    lines = simulate(args.out)
    print(f"Simulated honeypot session written: {args.out} ({len(lines)} lines, attacker {ATTACKER_IP})")
    print("No network port was opened. Analyse it with: python -m creox_aegis.cli " + args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
