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
    incidents = list_incidents()
    total = len(incidents)
    highest = max((i["risk_score"] for i in incidents), default=0)
    ips = len({i["ip"] for i in incidents})

    def risk_class(r: int) -> str:
        return "high" if r >= 85 else ("med" if r >= 70 else "low")

    def risk_label(r: int) -> str:
        return "CRITICAL" if r >= 85 else ("HIGH" if r >= 70 else "MEDIUM")

    cards = "".join(
        f"<div class='card'><div class='card-num'>{inc['risk_score']}</div>"
        f"<div class='card-label'>{risk_label(inc['risk_score'])} · {inc['ip']}</div>"
        f"<div class='small'>{', '.join(inc['detectors'])}</div>"
        f"<div class='small'>{inc['first_seen']} → {inc['last_seen']}</div></div>"
        for inc in incidents[:6]
    )
    rows = "".join(
        f"<tr><td>{i['id']}</td><td><b>{i['ip']}</b></td>"
        f"<td><span class='badge {risk_class(i['risk_score'])}'>{i['risk_score']} · {risk_label(i['risk_score'])}</span></td>"
        f"<td>{', '.join(i['detectors'])}</td><td>{i['first_seen']} → {i['last_seen']}</td>"
        f"<td>{i['evidence_count']} lines</td></tr>"
        for i in incidents
    ) or "<tr><td colspan='6'>No incidents yet — open <a href='/docs'>/docs</a>, use POST /analyze, paste the sample log text, then refresh this page.</td></tr>"
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Creox Aegis — Dashboard</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;font-family:system-ui,Arial,sans-serif;background:#070b14;color:#e8eefc}}
header{{padding:22px 28px;background:linear-gradient(90deg,#0d1b33,#102a4d);border-bottom:3px solid #00e5a0}}
h1{{margin:0;font-size:26px}}h1 span{{color:#00e5a0}}.sub{{color:#9fb3d8;margin-top:6px}}
.wrap{{max-width:1020px;margin:auto;padding:20px}}
.stats{{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0}}
.stat{{flex:1;min-width:160px;background:#101c36;border:1px solid #24365e;border-radius:14px;padding:16px}}
.stat b{{font-size:30px;color:#00e5a0;display:block}}.stat span{{color:#9fb3d8}}
.cards{{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:14px;margin:16px 0}}
.card{{background:#101c36;border:1px solid #24365e;border-left:5px solid #ff4d5e;border-radius:14px;padding:14px}}
.card-num{{font-size:28px;font-weight:700}}.card-label{{font-weight:600;margin:4px 0}}.small{{color:#9fb3d8;font-size:13px}}
table{{width:100%;border-collapse:collapse;background:#101c36;border-radius:14px;overflow:hidden}}
th,td{{border-bottom:1px solid #24365e;padding:10px;text-align:left}}th{{color:#9fb3d8}}
.badge{{padding:4px 10px;border-radius:20px;font-weight:700;font-size:13px}}
.badge.high{{background:#ff4d5e;color:#fff}}.badge.med{{background:#ff9f2e;color:#111}}.badge.low{{background:#00e5a0;color:#111}}
a{{color:#00e5a0}}button{{background:#00e5a0;border:0;padding:10px 16px;border-radius:10px;font-weight:700;cursor:pointer}}
</style></head>
<body><header><h1>🛡️ Creox <span>Aegis</span> — Dashboard</h1>
<div class="sub">Autonomous Cyber Defense · Defensive only, lab only · Responses are suggestions needing human approval</div></header>
<div class="wrap">
<div class="stats">
<div class="stat"><b>{total}</b><span>Total incidents</span></div>
<div class="stat"><b>{highest}</b><span>Highest risk</span></div>
<div class="stat"><b>{ips}</b><span>Unique attacker IPs</span></div>
</div>
<button onclick="location.reload()">↻ Refresh</button>
<h2>Top incidents</h2><div class="cards">{cards or "<p>No incidents yet.</p>"}</div>
<h2>All incidents</h2>
<table><tr><th>ID</th><th>IP</th><th>Risk</th><th>Detectors</th><th>Timeline</th><th>Evidence</th></tr>{rows}</table>
<p>API docs: <a href="/docs">/docs</a> · Health: <a href="/health">/health</a> · Incidents JSON: <a href="/incidents">/incidents</a></p>
</div></body></html>"""
