"""Creox Aegis Phase 3 — FastAPI dashboard API + SQLite storage.

Defensive only, lab only. The API analyses log TEXT sent to it (or the
bundled sample logs) and stores incidents in a local SQLite file.
It never scans a real network, never auto-acts on a real system, and
every stored incident keeps its suggested (human-approval) response.

Run (on the laptop, after installing requirements):
    pip install -r requirements.txt
    python -m uvicorn creox_aegis.api:app --port 8000
    # then open http://127.0.0.1:8000/  (dashboard) or /docs (API docs)

Endpoints:
    GET  /           — simple HTML dashboard (incidents table)
    GET  /health     — {"status": "ok"}
    POST /analyze    — {"log_text": "..."} -> incidents (also saved)
    GET  /incidents  — all saved incidents
    GET  /incidents/{incident_id} — one incident with reasons
"""
import json
import os
import sqlite3

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .correlation import correlate
from .detectors import run_detectors
from .parser import parse_text

DB_PATH = os.environ.get("AEGIS_DB", "aegis.db")

app = FastAPI(title="Creox Aegis", version="0.3.0")


class AnalyzeRequest(BaseModel):
    log_text: str


def init_db(path: str = DB_PATH) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT, detectors TEXT, first_seen TEXT, last_seen TEXT,
                risk INTEGER, reasons TEXT, evidence_count INTEGER,
                suggested_response TEXT)"""
        )


def save_incidents(incidents, path: str = DB_PATH) -> list[int]:
    init_db(path)
    ids = []
    with sqlite3.connect(path) as conn:
        for inc in incidents:
            cur = conn.execute(
                "INSERT INTO incidents (ip, detectors, first_seen, last_seen, risk, reasons, evidence_count, suggested_response) VALUES (?,?,?,?,?,?,?,?)",
                (inc.ip, ",".join(inc.detectors), inc.first_ts, inc.last_ts, inc.risk,
                 json.dumps(inc.reasons), len(inc.evidence), inc.suggested_response),
            )
            ids.append(cur.lastrowid)
    return ids


def list_incidents(path: str = DB_PATH) -> list[dict]:
    init_db(path)
    with sqlite3.connect(path) as conn:
        rows = conn.execute(
            "SELECT id, ip, detectors, first_seen, last_seen, risk, reasons, evidence_count, suggested_response FROM incidents ORDER BY risk DESC, id DESC"
        ).fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r[0], "ip": r[1], "detectors": r[2].split(",") if r[2] else [],
            "first_seen": r[3], "last_seen": r[4], "risk_score": r[5],
            "reasons": json.loads(r[6]), "evidence_count": r[7],
            "suggested_response": r[8],
        })
    return out


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.3.0"}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    incidents = correlate(run_detectors(parse_text(req.log_text)))
    ids = save_incidents(incidents)
    return {"incidents_analysed": len(incidents),
            "incidents": [{**i.to_dict(), "db_id": db_id} for i, db_id in zip(incidents, ids)]}


@app.get("/incidents")
def incidents():
    return {"incidents": list_incidents()}


@app.get("/incidents/{incident_id}")
def incident(incident_id: int):
    for inc in list_incidents():
        if inc["id"] == incident_id:
            return inc
    return {"error": "incident not found"}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    rows = "".join(
        f"<tr><td>{i['id']}</td><td>{i['ip']}</td><td>{i['risk_score']}</td>"
        f"<td>{', '.join(i['detectors'])}</td><td>{i['first_seen']} → {i['last_seen']}</td></tr>"
        for i in list_incidents()
    ) or "<tr><td colspan='5'>No incidents yet — POST log text to /analyze first.</td></tr>"
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Creox Aegis Dashboard</title>
<style>body{{font-family:system-ui;background:#070b14;color:#e8eefc}}table{{border-collapse:collapse}}td,th{{border:1px solid #24365e;padding:8px}}</style></head>
<body><h1>🛡️ Creox Aegis — Dashboard</h1><p>Defensive only, lab only. Responses are suggestions needing human approval.</p>
<table><tr><th>ID</th><th>IP</th><th>Risk</th><th>Detectors</th><th>Timeline</th></tr>{rows}</table>
<p>API docs: <a href="/docs">/docs</a> · Health: <a href="/health">/health</a></p></body></html>"""
