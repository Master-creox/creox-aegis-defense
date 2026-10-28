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
    dash = round(326.7 * (highest / 100.0), 1)
    left = "".join(
        f"<div class='alert'><span class='dot {'red' if i['risk_score']>=85 else 'amber'}'></span><div><b>{i['ip']}</b><div class='small'>{', '.join(i['detectors'])}</div><div class='small'>{i['first_seen']} — {i['last_seen']}</div></div><b class='risk'>{i['risk_score']}</b></div>"
        for i in incidents[:5]
    ) or "<p class='small'>No incidents yet. Open <a href='/docs'>/docs</a>, use POST /analyze with the sample log, then refresh.</p>"
    rows = "".join(
        f"<tr><td>{i['id']}</td><td><b>{i['ip']}</b></td><td>{i['risk_score']}</td><td>{', '.join(i['detectors'])}</td><td>{i['first_seen']} — {i['last_seen']}</td></tr>"
        for i in incidents
    ) or "<tr><td colspan='5'>No incidents yet.</td></tr>"
    # Professional network-graph SVG (nodes + links, no emoji, no cartoon globe)
    nodes = [(60,60),(140,40),(220,70),(110,120),(190,130),(260,50),(300,120),(170,180),(240,180)]
    links = [(0,1),(1,2),(1,3),(3,4),(2,5),(5,6),(3,7),(4,8),(6,8),(7,8)]
    svg_links = "".join(f"<line x1='{nodes[a][0]}' y1='{nodes[a][1]}' x2='{nodes[b][0]}' y2='{nodes[b][1]}' stroke='#155e75' stroke-width='1'/>" for a,b in links)
    svg_nodes = "".join(f"<circle cx='{x}' cy='{y}' r='5' fill='#22d3ee'/><circle cx='{x}' cy='{y}' r='10' fill='none' stroke='#164e63'/>" for x,y in nodes)
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Creox Aegis — Threat Detection &amp; Response</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;font-family:'Segoe UI',system-ui,Arial,sans-serif;background:#050a12;color:#dbeafe}}
header{{padding:16px 28px;background:#08111e;border-bottom:1px solid #1e3a5f;display:flex;justify-content:space-between;align-items:center}}
.brand{{font-size:19px;font-weight:700;letter-spacing:2px}} .brand span{{color:#22d3ee}}
.tag{{color:#94a3b8;font-size:12px;letter-spacing:1px;margin-top:2px}}
.grid{{display:grid;grid-template-columns:1fr 1.4fr 1fr;gap:14px;padding:14px}}@media(max-width:900px){{.grid{{grid-template-columns:1fr}}}}
.panel{{background:#0a1526;border:1px solid #1e3a5f;border-radius:8px;padding:18px}}
.panel h2{{margin:0 0 14px;font-size:12px;letter-spacing:2px;color:#7dd3fc;text-transform:uppercase}}
.alert{{display:flex;gap:10px;align-items:flex-start;border-bottom:1px solid #1e3a5f;padding:10px 0}}
.dot{{width:9px;height:9px;border-radius:50%;margin-top:5px;flex-shrink:0}}.dot.red{{background:#f43f5e}}.dot.amber{{background:#f59e0b}}
.risk{{margin-left:auto;color:#f43f5e}}.small{{color:#94a3b8;font-size:13px;line-height:1.5}}
.pipeline{{display:flex;justify-content:space-between;margin-top:16px}}
.step{{text-align:center;flex:1;border-top:2px solid #155e75;padding-top:10px;font-size:12px;letter-spacing:1px;color:#94a3b8}}
.step b{{display:block;color:#e2e8f0;font-size:14px;letter-spacing:0}}
.check{{color:#e2e8f0;margin:9px 0;font-size:14px}} .check span{{color:#34d399;margin-right:8px}}
.gauge{{display:flex;flex-direction:column;align-items:center;gap:6px}}
.gauge-wrap{{position:relative;width:150px;height:150px}}
.gauge-wrap svg{{display:block}} .gauge-center{{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}}
.gauge-num{{font-size:32px;font-weight:800}} .gauge-label{{font-size:11px;letter-spacing:1px;color:#94a3b8}}
.legend{{font-size:13px;color:#94a3b8;line-height:1.9;text-align:center}}
button{{background:#22d3ee;border:0;padding:9px 16px;border-radius:6px;font-weight:700;cursor:pointer;color:#082f49}}
table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid #1e3a5f;padding:10px;text-align:left;font-size:14px}}th{{color:#7dd3fc;font-size:12px;letter-spacing:1px;text-transform:uppercase}}
a{{color:#22d3ee}}
</style></head><body>
<header><div><div class="brand">CREOX <span>AEGIS</span></div><div class="tag">THREAT DETECTION &amp; RESPONSE — SECURITY OPERATIONS</div></div><button onclick="location.reload()">Refresh</button></header>
<div class="grid">
<div class="panel"><h2>Active Incidents — {total}</h2>{left}
<h2 style="margin-top:18px">Lab Overview</h2>
<div class="small">Unique attacker IPs: <b style="color:#fff">{ips}</b><br>Evidence lines analysed: <b style="color:#fff">{evidence}</b><br>Detectors active: <b style="color:#fff">5</b> — brute force, port scan, credential stuffing, SQLi probe, burst</div></div>
<div class="panel"><h2>Threat Network — Lab View</h2>
<svg width="100%" viewBox="0 0 340 210" style="background:#071426;border-radius:6px">{svg_links}{svg_nodes}</svg>
<div class="small" style="text-align:center;margin-top:8px">Lab visualisation only — incidents are from analysed log files, not real-world traffic.</div>
<div class="pipeline"><div class="step"><b>01</b>Detect</div><div class="step"><b>02</b>Analyse</div><div class="step"><b>03</b>Contain</div><div class="step"><b>04</b>Respond</div><div class="step"><b>05</b>Recover</div></div></div>
<div class="panel"><h2>AI Analysis</h2>
<div class="check"><span>✓</span>Correlating events by IP &amp; time</div>
<div class="check"><span>✓</span>Detecting anomalous behaviour</div>
<div class="check"><span>✓</span>Prioritising true positives</div>
<div class="check"><span>✓</span>Recommending response actions</div>
<div class="small">Every alert shows its reason and evidence lines — no black-box score.</div>
<h2 style="margin-top:18px">Risk &amp; Severity</h2>
<div class="gauge"><div class="gauge-wrap"><svg width="150" height="150" viewBox="0 0 140 140"><circle cx="70" cy="70" r="52" fill="none" stroke="#1e3a5f" stroke-width="12"/><circle cx="70" cy="70" r="52" fill="none" stroke="#f43f5e" stroke-width="12" stroke-dasharray="{dash} 326.7" stroke-linecap="round" transform="rotate(-90 70 70)"/></svg><div class="gauge-center"><div class="gauge-num">{highest}</div><div class="gauge-label">HIGHEST RISK</div></div></div>
<div class="legend">Critical: {crit} &nbsp;·&nbsp; High: {high} &nbsp;·&nbsp; Medium / Low: {med}</div></div></div>
</div>
<div style="padding:0 14px 20px"><div class="panel"><h2>All Incidents — Timeline &amp; Detail</h2>
<table><tr><th>ID</th><th>IP</th><th>Risk</th><th>Detectors</th><th>Timeline</th></tr>{rows}</table>
<p class="small">Defensive only, lab only. Responses are suggestions needing human approval. API docs: <a href="/docs">/docs</a> · Health: <a href="/health">/health</a> · JSON: <a href="/incidents">/incidents</a></p></div></div>
</body></html>"""
