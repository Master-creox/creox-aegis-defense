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
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .correlation import correlate
from .detectors import run_detectors
from .parser import parse_text
from .real_threats import get_real_threats

DB_PATH = os.environ.get("AEGIS_DB", "aegis.db")

app = FastAPI(title="Creox Aegis", version="0.3.0")
_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")


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


@app.get("/status")
def status():
    from .real_threats import _cache
    incidents = list_incidents()
    return {"service": "online", "version": "0.3.0", "incidents": len(incidents),
            "highest_risk": max((i["risk_score"] for i in incidents), default=0),
            "detectors_active": 5, "real_threats_cached": len(_cache["data"]),
            "server_time_utc": __import__("datetime").datetime.utcnow().isoformat() + "Z"}


@app.get("/real-threats")
def real_threats(limit: int = 30):
    try:
        threats = get_real_threats(limit=min(limit, 50))
        return {"source": "Emerging Threats Block-IPs (public blocklist)", "count": len(threats), "note": "Known malicious IPs reported publicly; locations are approximate city/region geolocation, not exact attacker locations, and not attacks on this system.", "threats": threats}
    except Exception as exc:
        return {"source": "Emerging Threats Block-IPs (public blocklist)", "count": 0, "error": str(exc), "threats": []}


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
    nodes = [(60,60),(140,40),(220,70),(110,120),(190,130),(260,50),(300,120),(170,180),(240,180)]
    links = [(0,1),(1,2),(1,3),(3,4),(2,5),(5,6),(3,7),(4,8),(6,8),(7,8)]
    svg_links = "".join(f"<line x1='{nodes[a][0]}' y1='{nodes[a][1]}' x2='{nodes[b][0]}' y2='{nodes[b][1]}' stroke='#0e7490' stroke-width='1'/>" for a,b in links)
    svg_nodes = "".join(f"<circle class='pulse-node' cx='{x}' cy='{y}' r='5' fill='#22d3ee'/>" for x,y in nodes)
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Creox Aegis — Threat Detection &amp; Response</title>
<script src="/static/index.js"></script>
<script src="/static/map.js"></script>
<script src="/static/geodata/worldLow.js"></script>
<script src="/static/themes/Animated.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600;800&family=Rajdhani:wght@500;600;700&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box}}body{{margin:0;font-family:'Rajdhani',system-ui,Arial,sans-serif;background:#020617;color:#dbeafe;overflow-x:hidden}}
body::before{{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(34,211,238,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(34,211,238,.06) 1px,transparent 1px);background-size:44px 44px;pointer-events:none}}
header{{position:relative;padding:16px 28px;background:linear-gradient(90deg,#04121f,#071a2e);border-bottom:1px solid #22d3ee;display:flex;justify-content:space-between;align-items:center;box-shadow:0 0 30px rgba(34,211,238,.25)}}
.brand{{font-family:'Orbitron',sans-serif;font-size:20px;font-weight:800;letter-spacing:3px}} .brand span{{color:#22d3ee;text-shadow:0 0 18px #22d3ee}}
.tag{{color:#67e8f9;font-size:11px;letter-spacing:3px;margin-top:3px}}
.status{{font-size:12px;letter-spacing:2px;color:#34d399}} .status b{{color:#34d399}}
.grid{{position:relative;display:grid;grid-template-columns:1fr 1.4fr 1fr;gap:14px;padding:14px}}@media(max-width:900px){{.grid{{grid-template-columns:1fr}}}}
.panel{{position:relative;background:linear-gradient(180deg,rgba(8,47,73,.55),rgba(2,6,23,.85));border:1px solid rgba(34,211,238,.35);border-radius:4px;padding:18px;backdrop-filter:blur(6px);box-shadow:0 0 24px rgba(34,211,238,.12) inset}}
.panel::before,.panel::after{{content:'';position:absolute;width:18px;height:18px;border-color:#22d3ee;border-style:solid}}
.panel::before{{top:-1px;left:-1px;border-width:2px 0 0 2px}} .panel::after{{bottom:-1px;right:-1px;border-width:0 2px 2px 0}}
.panel h2{{margin:0 0 14px;font-family:'Orbitron',sans-serif;font-size:12px;letter-spacing:3px;color:#67e8f9;text-transform:uppercase}}
.alert{{display:flex;gap:10px;align-items:flex-start;border-bottom:1px solid rgba(34,211,238,.2);padding:10px 0}}
.dot{{width:9px;height:9px;border-radius:50%;margin-top:5px;flex-shrink:0;box-shadow:0 0 12px currentColor}}.dot.red{{background:#f43f5e;color:#f43f5e}}.dot.amber{{background:#f59e0b;color:#f59e0b}}
.risk{{margin-left:auto;color:#f43f5e;text-shadow:0 0 12px #f43f5e}}.small{{color:#94a3b8;font-size:14px;line-height:1.5}}
.radar{{position:relative;width:280px;height:280px;margin:8px auto;border-radius:50%;border:1px solid rgba(34,211,238,.6);background:radial-gradient(circle at 50% 50%,#0e3a5e 0%,#071a2e 55%,#020617 100%);overflow:hidden;box-shadow:0 0 50px rgba(34,211,238,.4),0 0 18px rgba(34,211,238,.3) inset}}
.radar::before{{content:'';position:absolute;inset:0;border-radius:50%;background:conic-gradient(from 0deg,rgba(34,211,238,.45),transparent 22%);animation:sweep 4s linear infinite}}
@keyframes sweep{{to{{transform:rotate(360deg)}}}} @keyframes maprotate{{to{{transform:rotate(360deg)}}}} @keyframes sheen{{0%{{transform:translateX(-120%) skewX(-18deg)}}100%{{transform:translateX(220%) skewX(-18deg)}}}} @keyframes blip{{0%{{opacity:0;transform:scale(.6)}}25%{{opacity:1;transform:scale(1.4)}}100%{{opacity:0;transform:scale(2.2)}}}} @keyframes glowpulse{{0%,100%{{box-shadow:0 0 24px rgba(34,211,238,.25)}}50%{{box-shadow:0 0 44px rgba(34,211,238,.55)}}}} .panel{{animation:glowpulse 5s ease-in-out infinite}}
.pulse-node{{animation:pulse 2s ease-in-out infinite}} @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.35}}}}
.pipeline{{display:flex;justify-content:space-between;margin-top:16px}}
.step{{text-align:center;flex:1;border-top:2px solid #22d3ee;padding-top:10px;font-size:12px;letter-spacing:2px;color:#94a3b8}}
.step b{{display:block;color:#fff;font-family:'Orbitron',sans-serif;font-size:15px;letter-spacing:0}}
.check{{color:#e2e8f0;margin:9px 0;font-size:15px}} .check span{{color:#34d399;margin-right:8px;text-shadow:0 0 10px #34d399}}
.gauge{{display:flex;flex-direction:column;align-items:center;gap:6px}}
.gauge-wrap{{position:relative;width:150px;height:150px;filter:drop-shadow(0 0 14px rgba(244,63,94,.55))}}
.gauge-wrap svg{{display:block}} .gauge-center{{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}}
.gauge-num{{font-family:'Orbitron',sans-serif;font-size:34px;font-weight:800}} .gauge-label{{font-size:11px;letter-spacing:2px;color:#94a3b8}}
.legend{{font-size:13px;color:#94a3b8;line-height:1.9;text-align:center}}
button{{background:#22d3ee;border:0;padding:9px 18px;border-radius:4px;font-weight:700;cursor:pointer;color:#082f49;letter-spacing:1px;box-shadow:0 0 18px rgba(34,211,238,.6)}}
table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid rgba(34,211,238,.2);padding:10px;text-align:left;font-size:15px}}th{{color:#67e8f9;font-size:12px;letter-spacing:2px;text-transform:uppercase}}
a{{color:#22d3ee}}
</style></head><body>
<header><div><div class="brand">CREOX <span>AEGIS</span></div><div class="tag">THREAT DETECTION &amp; RESPONSE — SECURITY OPERATIONS</div></div><div class="status">● SYSTEM ONLINE · DEFENSE ACTIVE</div><button onclick="location.reload()">Refresh</button></header>
<div style="position:relative;display:flex;gap:22px;flex-wrap:wrap;padding:12px 28px;background:#071426;border-bottom:1px solid rgba(34,211,238,.3);font-size:13px;letter-spacing:1px">
<span>SERVICE: <b style="color:#34d399">ONLINE</b></span>
<span>INCIDENTS: <b>{total}</b></span>
<span>HIGHEST RISK: <b style="color:#f43f5e">{highest}</b></span>
<span>DETECTORS: <b>5 ACTIVE</b></span>
<span>REAL THREATS (FEED): <b id="feed-count">loading…</b></span>
<span id="live-time">LAST UPDATED: loading…</span>
</div>
<script>
fetch("/status").then(function(r){{return r.json();}}).then(function(d){{
  var f = document.getElementById("feed-count");
  if (f) f.textContent = d.real_threats_cached ? d.real_threats_cached + " cached" : "fetching via /real-threats…";
  var t = document.getElementById("live-time");
  if (t) t.textContent = "LAST UPDATED: " + new Date().toLocaleString("en-IN", {{timeZone: "Asia/Kolkata"}});
}}).catch(function(){{}});
</script>
<div class="grid">
<div class="panel"><h2>Active Incidents — {total}</h2>{left}
<h2 style="margin-top:18px">Lab Overview</h2>
<div class="small">Unique attacker IPs: <b style="color:#fff">{ips}</b><br>Evidence lines analysed: <b style="color:#fff">{evidence}</b><br>Detectors active: <b style="color:#fff">5</b> — brute force, port scan, credential stuffing, SQLi probe, burst</div></div>
<div class="panel"><h2>Threat Network — Lab View</h2>
<div id="chartdiv" style="width:100%;height:300px"></div>
<div id="real-note" class="small" style="text-align:center;margin-top:8px">Loading real threat IPs…</div>
<div class="small" style="text-align:center;margin-top:8px">Lab visualisation only — incidents are from analysed log files, not real-world traffic. Drag to spin the globe.</div>
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
<div style="position:relative;padding:0 14px 20px"><div class="panel"><h2>All Incidents — Timeline &amp; Detail</h2>
<table><tr><th>ID</th><th>IP</th><th>Risk</th><th>Detectors</th><th>Timeline</th></tr>{rows}</table>
<p class="small">Defensive only, lab only. Responses are suggestions needing human approval. API docs: <a href="/docs">/docs</a> · Health: <a href="/health">/health</a> · JSON: <a href="/incidents">/incidents</a></p></div></div>
<script>
try {{
if (typeof am5 === "undefined" || typeof am5map === "undefined") {{ throw new Error("amCharts CDN load nahi hua"); }}
var root = am5.Root.new("chartdiv");
root.setThemes([am5themes_Animated.new(root)]);
var chart = root.container.children.push(am5map.MapChart.new(root, {{
  panX: "rotateX", panY: "rotateY", projection: am5map.geoOrthographic(),
  homeZoomLevel: 0.95, zoomLevel: 0.95, minZoomLevel: 0.5, animationDuration: 800
}}));
var polygonSeries = chart.series.push(am5map.MapPolygonSeries.new(root, {{ geoJSON: am5geodata_worldLow }}));
polygonSeries.mapPolygons.template.setAll({{ fill: am5.color(0x0e7490), stroke: am5.color(0x67e8f9), strokeWidth: 1, tooltipText: "{{name}}", interactive: true }});
polygonSeries.mapPolygons.template.states.create("hover", {{ fill: am5.color(0x22d3ee), fillOpacity: 1 }});
var spin = chart.animate({{ key: "rotationX", from: 0, to: 360, duration: 30000, loops: Infinity }});
chart.appear(1000, 100);
fetch("/real-threats").then(function(r){{return r.json();}}).then(function(data){{
  if (!data.threats || !data.threats.length) return;
  var pointSeries = chart.series.push(am5map.MapPointSeries.new(root, {{}}));
  pointSeries.bullets.push(function(){{ return am5.Bullet.new(root, {{ sprite: am5.Circle.new(root, {{ radius: 4, fill: am5.color(0xf43f5e), stroke: am5.color(0xffffff), strokeWidth: 1 }}) }}); }});
  data.threats.forEach(function(t){{ pointSeries.pushDataItem({{ latitude: t.lat, longitude: t.lon, title: t.ip + " — " + t.country }}); }});
  var note = document.getElementById("real-note"); if (note) note.textContent = "Real threats on globe: " + data.count + " known malicious IPs (" + data.source + "). Locations approximate.";
}}).catch(function(){{}});
}} catch (e) {{
  document.getElementById("chartdiv").innerHTML = "<p style='text-align:center;padding:110px 20px;color:#fca5a5'>Globe load nahi hua: " + e.message + "<br>Browser me F12 → Console me error check karo, ya page ko Ctrl+F5 se hard refresh karo.</p>";
}}
</script>
</body></html>"""
