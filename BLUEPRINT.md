# Creox Aegis — Autonomous Cyber Defense — Blueprint (DRAFT, 2026-10-28)

**Owner:** Akash Kumar (Master Creox), BCA Cybersecurity
**Status:** Blueprint FINAL (locked 2026-10-28) — v1 built + pushed (see below).
**Chosen:** 2026-10-28, first of his 5 new ideas.

## Name note — IMPORTANT
"Creox Aegis" is close to "Aegis Prime" (his existing AI HUD companion, BAOS A003 name).
To avoid confusion, this project must be presented as a SEPARATE defensive platform, not the HUD:
- Aegis Prime = personal AI HUD companion (desktop app, voice, character).
- Creox Aegis = autonomous cyber defense platform (log analysis, detection, timeline, response suggestions).
- Suggested repo name: `creox-aegis-defense` (to be confirmed by Akash; alternative: `creox-aegis`).

## Purpose (Akash's words, locked)
An AI-powered defensive security platform that detects suspicious activity, builds an attack timeline, and suggests a safe response.
Defensive ONLY. It does NOT attack, exploit, or access any real system, account, or network without the owner's clear permission.

## Core modules (v1 scope)
1. **Real-time log analysis** — ingest sample/lab logs (auth logs, web logs, firewall-style logs) in a safe, offline parser. No live sniffing of other people's traffic.
2. **Threat correlation** — link related events by IP / user / time window (e.g. many failed logins + a port scan from the same IP = one incident, not 50 separate alerts).
3. **Risk scoring** — explainable score per incident (e.g. failed-login count, scan breadth, time pattern), with the reason shown, not a black-box number.
4. **Explainable AI alerts** — every alert says WHAT happened, WHY it was flagged, and WHAT evidence supports it (log lines, counts, timeline).
5. **Attack timeline** — chronological reconstruction of one incident from first probe to last event.
6. **Isolated honeypot lab** — a SIMULATED honeypot (fake service in the lab, no real exposure, no real data). Attackers in the simulation are test scripts Akash runs himself. The honeypot must never be opened to the real internet.
7. **Safe response suggestions** — suggest-only by default: block IP (in lab), reset password, disable account, patch, isolate host — with a human approval step before any real action. Lab auto-block is allowed ONLY inside the simulated lab, never on a production/real system.

## What it is NOT
- Not a replacement for SentinelAI: SentinelAI is a live-traffic SOC guard with autonomous IP blocking in its own demo. Creox Aegis is a broader defense platform: log + correlation + timeline + honeypot + suggested response, with explainability as the headline.
- Not a hacking tool, not malware, not a scanner for real targets.
- Not Aegis Prime: no voice, no character, no HUD companion features in v1.

## Proposed stack (to confirm)
Python (zero-dependency detector core, like the sniffer), FastAPI for the dashboard API, SQLite for incidents/alerts, HTML dashboard (same style as his other projects). Tests with pytest on bundled sample logs, so results are reproducible.

## Phases
- **Phase 1 (v1):** Log parser + 5 detectors (brute force, port scan, credential stuffing pattern, web probe/SQLi pattern in logs, DDoS-like burst) + correlation + risk score + timeline + text/JSON report. All on bundled sample logs.
- **Phase 2:** Simulated honeypot lab + honeypot log ingestion into the same timeline.
- **Phase 3:** FastAPI dashboard (incidents, timeline view, alert detail with explanation) + exportable report.

## Test / demo data
Bundled fictional sample logs only (no real user data, no real IPs of real people). Every benchmark number must come from those sample logs and be reproducible by running the tests.

## Decisions LOCKED (Akash, 2026-10-28)
1. Repo name: `creox-aegis-defense` — created by Akash, PUBLIC.
2. Response mode: **suggest-only** everywhere (no lab auto-block either).
3. Visibility: PUBLIC from day 1.
4. Stack: **Python + FastAPI + SQLite approved.** v1 ships the Python detector core as a CLI (zero dependencies, tested); FastAPI + SQLite dashboard is Phase 3, as planned.

## v1 DONE (2026-10-28, verified)
- Repo `Master-creox/creox-aegis-defense` (main, public), commit `bae2e1c7`.
- Files: README.md, LICENSE (MIT), BLUEPRINT.md, creox_aegis/ (parser, detectors, correlation, cli), tests/test_aegis.py, sample_logs/sample.log.
- Tests: 7/7 pass (unittest). CLI on sample log: 22 events → 1 incident, IP 192.168.1.50, risk 95/100, detectors brute_force + port_scan + web_probe_sqli_pattern, normal user 192.168.1.10 clean.
