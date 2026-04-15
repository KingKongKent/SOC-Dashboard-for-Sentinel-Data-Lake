#!/usr/bin/env python3
"""One-off: re-fetch incidents from Graph to capture redirectIncidentId."""
import os, sys, json
os.environ.setdefault("DB_PATH", "/var/lib/soc-dashboard/soc_dashboard.db")
sys.path.insert(0, "/opt/soc-dashboard")

import requests
from fetch_live_data import get_graph_access_token, GRAPH_API_BASE, _map_graph_incident
from database import insert_incident
import sqlite3

token = get_graph_access_token()
headers = {"Authorization": f"Bearer {token}"}
all_raw = []
url = f"{GRAPH_API_BASE}/security/incidents"
params = {"$top": 50, "$orderby": "createdDateTime desc", "$expand": "alerts"}
for _ in range(4):
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    all_raw.extend(data.get("value", []))
    url = data.get("@odata.nextLink")
    if not url:
        break
    params = None

redirected = [i for i in all_raw if (i.get("status") or "").lower() == "redirected"]
print(f"Found {len(redirected)} redirected in raw API response")
for inc in redirected[:3]:
    print(f"  #{inc.get('id')} -> redirectIncidentId={inc.get('redirectIncidentId', 'MISSING')}")

mapped = [_map_graph_incident(i) for i in all_raw]
for m in mapped:
    insert_incident(m)
print(f"Re-inserted {len(mapped)} incidents with redirect field")

conn = sqlite3.connect(os.environ["DB_PATH"])
cur = conn.cursor()
cur.execute("SELECT id, data FROM incidents WHERE LOWER(status)='redirected' LIMIT 3")
for r in cur.fetchall():
    d = json.loads(r[1])
    print(f"  DB #{r[0]}: redirectIncidentId={d.get('redirectIncidentId', 'NONE')}")
