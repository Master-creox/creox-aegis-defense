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
    evidence = sum(i["evidence_count"] for i in incidents)
    crit = sum(1 for i in incidents if i["risk_score"] >= 85)
    high = sum(1 for i in incidents if 70 <= i["risk_score"] < 85)
    med = sum(1 for i in incidents if i["risk_score"] < 70)
    # Gauge: donut arc for highest risk (0-100)
    import math
    pct = highest / 100.0
    # SVG circle r=52, circumference ~326.7
    dash = round(326.7 * pct, 1)
    left = "".join(
        f"<div class='alert'><span class='dot {'red' if i['risk_score']>=85 else 'amber'}'></span><div><b>{i['ip']}</b><br><span class='small'>{', '.join(i['detectors'])}</span><br><span class='small'>{i['first_seen']} → {i['last_seen']}</span></div><b class='risk'>{i['risk_score']}</b></div>"
        for i in incidents[:5]
    ) or "<p class='small'>No incidents yet — open <a href='/docs'>/docs</a>, POST /analyze with the sample log, then refresh.</p>"
    rows = "".join(
        f"<tr><td>{i['id']}</td><td><b>{i['ip']}</b></td><td>{i['risk_score']}</td><td>{', '.join(i['detectors'])}</td><td>{i['first_seen']} → {i['last_seen']}</td></tr>"
        for i in incidents
    ) or "<tr><td colspan='5'>No incidents yet.</td></tr>"
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Creox Aegis — Threat Detection &amp; Response</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;font-family:system-ui,Arial,sans-serif;background:#04070f;color:#dbeafe}}
header{{padding:16px 24px;background:#071426;border-bottom:2px solid #00e5ff;display:flex;justify-content:space-between;align-items:center}}
header h1{{margin:0;font-size:20px;letter-spacing:1px}}header h1 span{{color:#00e5ff}}
.grid{{display:grid;grid-template-columns:1fr 1.4fr 1fr;gap:14px;padding:14px}}@media(max-width:900px){{.grid{{grid-template-columns:1fr}}}}
.panel{{background:linear-gradient(180deg,#0a1c33,#071426);border:1px solid #1e3a5f;border-radius:14px;padding:16px}}
.panel h2{{margin:0 0 12px;font-size:14px;letter-spacing:1px;color:#7dd3fc}}
.alert{{display:flex;gap:10px;align-items:flex-start;border-bottom:1px solid #1e3a5f;padding:10px 0}}
.dot{{width:10px;height:10px;border-radius:50%;margin-top:5px;flex-shrink:0}}.dot.red{{background:#ff4d5e;box-shadow:0 0 10px #ff4d5e}}.dot.amber{{background:#ff9f2e}}
.risk{{margin-left:auto;color:#ff4d5e}}.small{{color:#94a3b8;font-size:13px}}
.orb{{width:200px;height:200px;margin:10px auto;border-radius:50%;background:radial-gradient(circle at 35% 35%,#38bdf8,#0b3a6b 55%,#04070f 80%);border:1px solid #38bdf8;box-shadow:0 0 40px #0ea5e9 inset,0 0 30px #0ea5e9;display:flex;align-items:center;justify-content:center;font-size:44px}}
.pipeline{{display:flex;justify-content:space-between;text-align:center;margin-top:14px;color:#7dd3fc;font-size:13px}}
.pipeline b{{display:block;color:#fff;font-size:14px}}
.check{{color:#34d399;margin:8px 0}}
.gauge{{text-align:center}}.gauge svg{{transform:rotate(-90deg)}}.gauge-num{{font-size:30px;font-weight:800;margin-top:-78px}}
.legend{{font-size:13px;color:#94a3b8;line-height:1.9}}
button{{background:#00e5ff;border:0;padding:10px 16px;border-radius:10px;font-weight:700;cursor:pointer}}
table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid #1e3a5f;padding:9px;text-align:left}}th{{color:#7dd3fc}}
a{{color:#00e5ff}}
</style></head><body>
<header><h1>🛡️ CREOX <span>AEGIS</span> — THREAT DETECTION &amp; RESPONSE</h1><button onclick="location.reload()">↻ Refresh</button></header>
<div class="grid">
<div class="panel"><h2>ACTIVE INCIDENTS · {total}</h2>{left}
<h2 style="margin-top:16px">LAB OVERVIEW</h2>
<div class="small">Unique attacker IPs: <b style="color:#fff">{ips}</b><br>Evidence lines analysed: <b style="color:#fff">{evidence}</b><br>Detectors active: <b style="color:#fff">5</b> (brute force, port scan, credential stuffing, SQLi probe, burst)</div></div>
<div class="panel"><h2>GLOBAL THREAT VIEW — LAB NETWORK</h2>
<div class="orb">🌐</div>
<div class="small" style="text-align:center">Live view is a lab visualisation — incidents above are from analysed log files, not real-world traffic.</div>
<div class="pipeline"><div>🔍<b>Detect</b></div><div>📊<b>Analyse</b></div><div>🔒<b>Contain</b></div><div>⚡<b>Respond</b></div><div>♻️<b>Recover</b></div></div></div>
<div class="panel"><h2>AI ANALYSIS</h2>
<div class="check">✓ Correlating events by IP &amp; time</div>
<div class="check">✓ Detecting anomalous behaviour</div>
<div class="check">✓ Prioritising true positives</div>
<div class="check">✓ Recommending response actions</div>
<div class="small">Every alert shows its reason + evidence lines — no black-box score.</div>
<h2 style="margin-top:16px">RISK &amp; SEVERITY</h2>
<div class="gauge"><svg width="140" height="140" viewBox="0 0 140 140"><circle cx="70" cy="70" r="52" fill="none" stroke="#1e3a5f" stroke-width="14"/><circle cx="70" cy="70" r="52" fill="none" stroke="#ff4d5e" stroke-width="14" stroke-dasharray="{dash} 326.7" stroke-linecap="round"/></svg><div class="gauge-num">{highest}</div><div class="small">Highest Risk Score</div></div>
<div class="legend">🔴 Critical: {crit} &nbsp; 🟠 High: {high} &nbsp; 🟢 Medium/Low: {med}</div></div>
</div>
<div style="padding:0 14px 20px"><div class="panel"><h2>ALL INCIDENTS — TIMELINE &amp; DETAIL</h2>
<table><tr><th>ID</th><th>IP</th><th>Risk</th><th>Detectors</th><th>Timeline</th></tr>{rows}</table>
<p class="small">Defensive only, lab only. Responses are suggestions needing human approval. API docs: <a href="/docs">/docs</a> · Health: <a href="/health">/health</a> · JSON: <a href="/incidents">/incidents</a></p></div></div>
</body></html>"""
