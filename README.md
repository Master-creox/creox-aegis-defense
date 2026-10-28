# Creox Aegis — Autonomous Cyber Defense

**Owner:** Akash Kumar (Master Creox), BCA Cybersecurity
**Status:** v1 — defensive log analysis, correlation, timeline, suggested response.
**Scope: DEFENSIVE ONLY, LAB ONLY.**

Creox Aegis is NOT Aegis Prime. Aegis Prime is a personal AI HUD companion.
Creox Aegis is a separate defensive platform: it reads log files, detects
suspicious patterns, correlates them into one incident per attacker IP,
scores the risk with a plain-language explanation, builds a timeline, and
**suggests** a safe response. It never attacks, exploits, or accesses a
real system, account, or network without the owner's clear permission, and
it never auto-acts on a real system — every suggested response needs
human approval first.

## v1 features
- Log parser (fictional/lab log format, documented in `creox_aegis/parser.py`)
- 5 explainable detectors: brute force, port scan, credential stuffing,
  web SQLi-pattern probe, traffic burst
- Correlation: many findings from one IP → one incident, one timeline
- Risk scoring with reasons + evidence (every alert shows its log lines)
- Suggested response (suggest-only; lab auto-block only in a simulated lab)
- CLI + JSON report

## Run it (no install, zero dependencies, Python 3.10+)
```bash
python -m creox_aegis.cli sample_logs/ --json report.json
```

## Tests (unittest, zero dependencies)
```bash
python -m unittest discover -s tests -v
```
Expected on the bundled sample log: 22 events, 1 incident (attacker
192.168.1.50, brute force + port scan + SQLi probe), normal user
192.168.1.10 produces no incident. All 7 tests pass.

## Roadmap
- Phase 2: simulated honeypot lab (fake service, lab only, never internet-facing)
- Phase 3: FastAPI dashboard + exportable report

## Boundaries (never to be added)
- No real-target scanning, exploitation, payloads, or malware.
- No password cracking against real accounts, no credential theft.
- No sniffing other people's traffic.
- Practice data is fictional sample logs only, plus Akash's own lab logs.
