"""Explainable detectors over parsed events.

Every finding carries its evidence (the log lines that triggered it) and a
plain-language reason, so an alert is never a black-box number.
Thresholds are deliberately simple and documented — this is a teaching /
lab defense platform, not a black-box ML claim.
"""
import re
from collections import defaultdict
from dataclasses import dataclass, field

from .parser import Event

SQLI_RE = re.compile(r"(?i)(\bor\s+1\s*=\s*1\b|union\s+select|'\s*or\s*')")


@dataclass
class Finding:
    detector: str
    ip: str
    count: int
    first_ts: str
    last_ts: str
    reason: str
    evidence: list[str] = field(default_factory=list)
    risk: int = 0


def _by_ip(events: list[Event]) -> dict[str, list[Event]]:
    out: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.ip and e.ip != "unknown":
            out[e.ip].append(e)
    return out


def _window(evs: list[Event]) -> tuple[str, str]:
    ts = [e.iso() for e in evs if e.ts]
    return (ts[0], ts[-1]) if ts else ("", "")


def detect_brute_force(events: list[Event], threshold: int = 5) -> list[Finding]:
    out = []
    for ip, evs in _by_ip(events).items():
        failed = [e for e in evs if e.kind == "FAILED_LOGIN"]
        if len(failed) >= threshold:
            first, last = _window(failed)
            out.append(Finding(
                "brute_force", ip, len(failed), first, last,
                f"{len(failed)} failed logins from one IP — a password-guessing pattern, not normal user mistakes.",
                [e.raw for e in failed], risk=min(40 + len(failed) * 2, 80)))
    return out


def detect_port_scan(events: list[Event], threshold: int = 10) -> list[Finding]:
    out = []
    for ip, evs in _by_ip(events).items():
        probes = [e for e in evs if e.kind == "PORT_PROBE"]
        ports = {re.search(r"port=(\d+)", e.detail).group(1)
                 for e in probes if re.search(r"port=(\d+)", e.detail)}
        if len(ports) >= threshold:
            first, last = _window(probes)
            out.append(Finding(
                "port_scan", ip, len(ports), first, last,
                f"{len(ports)} different ports probed from one IP — reconnaissance before an attack, not normal browsing.",
                [e.raw for e in probes], risk=70))
    return out


def detect_credential_stuffing(events: list[Event], threshold: int = 5) -> list[Finding]:
    """Many different users, same IP, failed logins = stolen-list testing."""
    out = []
    for ip, evs in _by_ip(events).items():
        failed = [e for e in evs if e.kind == "FAILED_LOGIN"]
        users = {re.search(r"user=(\S+)", e.detail).group(1)
                 for e in failed if re.search(r"user=(\S+)", e.detail)}
        if len(users) >= threshold and len(failed) >= threshold:
            first, last = _window(failed)
            out.append(Finding(
                "credential_stuffing", ip, len(failed), first, last,
                f"{len(users)} different usernames tried from one IP — a leaked credential list being tested.",
                [e.raw for e in failed], risk=75))
    return out


def detect_web_probe(events: list[Event]) -> list[Finding]:
    out = []
    for ip, evs in _by_ip(events).items():
        bad = [e for e in evs if e.kind == "WEB_REQUEST" and SQLI_RE.search(e.detail)]
        if bad:
            first, last = _window(bad)
            out.append(Finding(
                "web_probe_sqli_pattern", ip, len(bad), first, last,
                "Web request contains an SQL-injection pattern (e.g. OR 1=1) — an attempt to break the login/database query.",
                [e.raw for e in bad], risk=85))
    return out


def detect_burst(events: list[Event], threshold: int = 50) -> list[Finding]:
    """Very high event volume from one IP in the sample = DDoS-like burst."""
    out = []
    for ip, evs in _by_ip(events).items():
        if len(evs) >= threshold:
            first, last = _window(evs)
            out.append(Finding(
                "traffic_burst", ip, len(evs), first, last,
                f"{len(evs)} events from one IP in this log sample — a flood/burst pattern, not normal traffic.",
                [e.raw for e in evs[:10]], risk=60))
    return out


ALL_DETECTORS = [detect_brute_force, detect_port_scan,
                 detect_credential_stuffing, detect_web_probe, detect_burst]


def run_detectors(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    for fn in ALL_DETECTORS:
        findings.extend(fn(events))
    return sorted(findings, key=lambda f: -f.risk)
