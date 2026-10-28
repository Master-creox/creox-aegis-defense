"""Correlate findings from one IP into one incident with a timeline.

Why: 50 alerts for one attacker help nobody. One incident, one timeline,
one risk score, and one suggested response is what a defender acts on.
"""
from dataclasses import dataclass, field

from .detectors import Finding


@dataclass
class Incident:
    ip: str
    detectors: list[str]
    first_ts: str
    last_ts: str
    risk: int
    reasons: list[str]
    evidence: list[str]
    suggested_response: str

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "detectors": self.detectors,
            "first_seen": self.first_ts,
            "last_seen": self.last_ts,
            "risk_score": self.risk,
            "reasons": self.reasons,
            "evidence_count": len(self.evidence),
            "suggested_response": self.suggested_response,
        }


def suggest_response(risk: int, detectors: list[str]) -> str:
    if risk >= 85 or "web_probe_sqli_pattern" in detectors:
        return ("SUGGESTED (needs human approval before any real action): "
                "block the IP at the firewall in the LAB, force a password reset "
                "for affected accounts, and patch the login query with a prepared statement.")
    if risk >= 70:
        return ("SUGGESTED (needs human approval before any real action): "
                "temporarily block / rate-limit the IP in the LAB and enable account lockout "
                "after repeated failed logins.")
    return ("SUGGESTED: monitor the IP, enable stronger logging, and review "
            "whether the account passwords need rotation.")


def correlate(findings: list[Finding]) -> list[Incident]:
    by_ip: dict[str, list[Finding]] = {}
    for f in findings:
        by_ip.setdefault(f.ip, []).append(f)
    incidents = []
    for ip, fs in by_ip.items():
        risk = min(100, max(f.risk for f in fs) + 5 * (len(fs) - 1))
        ts = [f.first_ts for f in fs if f.first_ts] + [f.last_ts for f in fs if f.last_ts]
        evidence: list[str] = []
        for f in fs:
            evidence.extend(f.evidence)
        incidents.append(Incident(
            ip=ip,
            detectors=sorted({f.detector for f in fs}),
            first_ts=min(ts) if ts else "",
            last_ts=max(ts) if ts else "",
            risk=risk,
            reasons=[f.reason for f in fs],
            evidence=evidence,
            suggested_response=suggest_response(risk, [f.detector for f in fs]),
        ))
    return sorted(incidents, key=lambda i: -i.risk)
