"""Real-world threat feed for Creox Aegis — defensive display only.

Source: Emerging Threats Block-IPs list (public, curated malicious IPs).
https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt

Geolocation: ip-api.com batch lookup (free, no key). Locations are
approximate (city/region level) — IP geolocation is never exact.

This module never attacks, scans, or contacts the listed IPs. It only
reads a public blocklist and a public geolocation API, so the globe
can show where known malicious IPs are reported from.
"""
import time
import urllib.request
import json

FEED_URL = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
GEO_URL = "http://ip-api.com/batch"
_cache = {"at": 0, "data": []}
CACHE_SECONDS = 3600


def _fetch_feed(limit=200):
    req = urllib.request.Request(FEED_URL, headers={"User-Agent": "Creox-Aegis/0.3"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode("utf-8", "ignore")
    import ipaddress
    ips = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line[0].isdigit():
            token = line.split()[0]
            # CIDR ranges: use their network address as the representative IP
            # (ip-api rejects "1.10.16.0/20" itself, but accepts "1.10.16.0")
            if "/" in token:
                try:
                    token = str(ipaddress.ip_network(token, strict=False).network_address)
                except ValueError:
                    continue
            if token not in ips:
                ips.append(token)
            if len(ips) >= limit:
                break
    return ips


def _geolocate(ips):
    payload = json.dumps([{"query": ip, "fields": "query,country,lat,lon,status"} for ip in ips]).encode()
    req = urllib.request.Request(GEO_URL, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        results = json.loads(resp.read().decode())
    out = []
    for r in results:
        if r.get("status") == "success" and r.get("lat") is not None:
            out.append({"ip": r["query"], "country": r.get("country", ""), "lat": r["lat"], "lon": r["lon"]})
    return out


def get_real_threats(limit=30):
    now = time.time()
    if _cache["data"] and now - _cache["at"] < CACHE_SECONDS:
        return _cache["data"][:limit]
    ips = _fetch_feed(limit=100)
    threats = _geolocate(ips[:limit])
    if threats:
        _cache["at"] = now
        _cache["data"] = threats
    return threats
