"""Parse fictional/lab log lines into structured events.

Supported line format (all sample logs use this, no real data):
    2026-10-28T10:00:00Z 192.168.1.50 FAILED_LOGIN user=admin
    2026-10-28T10:01:00Z 192.168.1.50 PORT_PROBE port=22
    2026-10-28T10:02:00Z 192.168.1.50 WEB_REQUEST path=/login?id=1' OR '1'='1
    2026-10-28T10:03:00Z 192.168.1.50 SUCCESS_LOGIN user=admin
Lines that do not match are kept with kind="UNKNOWN" so nothing is silently dropped.
"""
import re
from dataclasses import dataclass
from datetime import datetime

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+"
    r"(?P<ip>\S+)\s+(?P<kind>\S+)(?:\s+(?P<rest>.*))?$"
)


@dataclass
class Event:
    ts: datetime | None
    ip: str
    kind: str
    raw: str
    detail: str = ""

    def iso(self) -> str:
        return self.ts.strftime("%Y-%m-%dT%H:%M:%SZ") if self.ts else ""


def parse_line(line: str) -> Event:
    line = line.strip()
    if not line:
        return Event(None, "", "EMPTY", line)
    m = LINE_RE.match(line)
    if not m:
        return Event(None, "unknown", "UNKNOWN", line, detail=line)
    ts = None
    try:
        ts = datetime.strptime(m.group("ts"), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        ts = None
    return Event(ts, m.group("ip"), m.group("kind"), line, detail=m.group("rest") or "")


def parse_text(text: str) -> list[Event]:
    return [parse_line(line) for line in text.splitlines() if line.strip()]


def parse_file(path: str) -> list[Event]:
    with open(path, encoding="utf-8") as f:
        return parse_text(f.read())
