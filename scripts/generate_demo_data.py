#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate demo/synthetic data for the SOC Dashboard.

Run standalone:
    python scripts/generate_demo_data.py              # writes dashboard_data.json
    python scripts/generate_demo_data.py --db          # also inserts into SQLite DB
    python scripts/generate_demo_data.py --count 50    # generate 50 incidents (default 100)
"""
import argparse
import json
import os
import random
import sys
from datetime import datetime, timedelta

# Allow importing project modules when run from repo root or scripts/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


# ── Demo entity pools ────────────────────────────────────────────────────────

DEMO_IPS = [
    '185.220.101.34', '45.155.205.233', '91.240.118.172', '194.165.16.77',
    '23.106.215.64', '103.253.41.98', '5.188.206.14', '162.247.74.27',
    '198.98.56.149', '209.141.45.189', '80.82.77.139', '141.98.11.105',
]

DEMO_DOMAINS = [
    'login-microsoftonline.tk', 'secure-update365.xyz', 'auth-verify.net',
    'payload-delivery.ru', 'c2-callback.cn', 'exfil-data.top',
]

DEMO_URLS = [
    'https://login-microsoftonline.tk/oauth2/token',
    'https://secure-update365.xyz/update.exe',
    'http://payload-delivery.ru/stage2.ps1',
]

DEMO_FILES = [
    'invoice_7291.exe', 'update_patch.dll', 'report_final.scr',
    'readme.hta', 'meeting_notes.js',
]

DEMO_SHA256 = [
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
    '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
]

DEMO_VERDICTS = ['malicious', 'suspicious', 'suspicious', 'unknown']

INCIDENT_TEMPLATES = [
    {'severity': 'Low',    'status': 'New',    'type': 'DLP'},
    {'severity': 'High',   'status': 'Active', 'type': 'Multi-stage'},
    {'severity': 'Medium', 'status': 'Closed', 'type': 'AnonymousIP'},
    {'severity': 'High',   'status': 'Active', 'type': 'PasswordSpray'},
    {'severity': 'Medium', 'status': 'New',    'type': 'Discovery'},
    {'severity': 'Low',    'status': 'Active', 'type': 'RemoteConnection'},
    {'severity': 'Medium', 'status': 'Closed', 'type': 'Hacktool'},
    {'severity': 'High',   'status': 'New',    'type': 'SuspiciousSignIn'},
]


# ── Generators ────────────────────────────────────────────────────────────────

def generate_demo_incidents(count: int = 100) -> list:
    """Generate *count* demo incidents with realistic entities."""
    incidents = []
    for i in range(count):
        t = INCIDENT_TEMPLATES[i % len(INCIDENT_TEMPLATES)]
        iid = 14021 + i
        days_ago = i // 4
        ts = datetime.now() - timedelta(days=days_ago, hours=random.randint(0, 23))

        entities = [{'type': 'user', 'name': f'user{iid}@contoso.com', 'verdict': 'suspicious'}]

        if i % 3 != 2:
            entities.append({
                'type': 'ip',
                'name': random.choice(DEMO_IPS),
                'verdict': random.choice(DEMO_VERDICTS),
            })
        if i % 4 == 0:
            entities.append({
                'type': 'mailbox',
                'name': f'user{iid}@{random.choice(DEMO_DOMAINS)}',
                'verdict': random.choice(DEMO_VERDICTS),
            })
        if t['type'] in ('DLP', 'Multi-stage', 'AnonymousIP'):
            entities.append({
                'type': 'url',
                'name': random.choice(DEMO_URLS),
                'verdict': random.choice(DEMO_VERDICTS),
            })
        if t['type'] in ('Hacktool', 'Multi-stage', 'Discovery'):
            fname = random.choice(DEMO_FILES)
            fidx = DEMO_FILES.index(fname)
            entities.append({
                'type': 'file',
                'name': fname,
                'verdict': random.choice(DEMO_VERDICTS),
                'sha256': DEMO_SHA256[fidx],
            })

        incidents.append({
            'id': str(iid),
            'title': f"{t['type']} incident #{iid}",
            'severity': t['severity'],
            'status': t['status'],
            'createdTime': ts.isoformat() + 'Z',
            'lastUpdateTime': ts.isoformat() + 'Z',
            'classification': 'unknown',
            'determination': 'unknown',
            'assignedTo': 'Unassigned',
            'alertCount': random.randint(1, 5),
            'entities': entities,
            'entityCount': len(entities),
            'mitreTechniques': [],
            'recommendations': ['Investigate alert details'],
            'webUrl': f'https://security.microsoft.com/incident2/{iid}/overview',
        })
    return incidents


def generate_demo_alerts(incidents: list) -> list:
    """Generate synthetic alerts from demo incidents."""
    alerts = []
    aid = 1000
    for inc in incidents:
        n = inc.get('alertCount', 1) or 1
        inc_time = datetime.fromisoformat(inc['createdTime'].replace('Z', ''))
        for _ in range(n):
            t = inc_time - timedelta(minutes=random.randint(0, 120))
            alerts.append({
                'id': str(aid),
                'incidentId': inc['id'],
                'title': f"Alert for {inc['title'][:40]}",
                'severity': inc['severity'],
                'category': 'SuspiciousActivity',
                'product': 'Microsoft Defender XDR',
                'timestamp': t.isoformat() + 'Z',
                'status': random.choice(['New', 'InProgress', 'Resolved']),
                'detectionSource': 'Demo',
            })
            aid += 1
    return alerts


def generate_demo_secure_score() -> dict:
    """Return realistic demo Secure Score data matching M365 structure."""
    return {
        'source': 'demo',
        'currentScore': 847.87,
        'maxScore': 1528,
        'percentage': 55.5,
        'controlScores': [],
        'categoryScores': [
            {'name': 'Identity', 'current': 233.7, 'max': 339.0, 'percentage': 68.9, 'controlCount': 67},
            {'name': 'Data',     'current': 8.0,   'max': 9.0,   'percentage': 88.9, 'controlCount': 4},
            {'name': 'Device',   'current': 484.1, 'max': 940.0, 'percentage': 51.5, 'controlCount': 128},
            {'name': 'Apps',     'current': 122.0, 'max': 240.0, 'percentage': 50.8, 'controlCount': 62},
        ],
        'recommendations': [],
        'recommendationsByCategory': {},
        'recentImprovements': [],
        'actionCounts': {'toAddress': 0, 'riskAccepted': 0, 'resolved': 0, 'regressed': 0},
        'trend': 0,
        'history': [],
    }


def generate_demo_daily_alerts(alerts: list) -> list:
    """Generate 30 days of daily alert volume from demo alerts."""
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    day_counts: dict[str, int] = {}
    for i in range(29, -1, -1):
        d = today - timedelta(days=i)
        day_counts[d.strftime('%Y-%m-%d')] = 0

    for alert in alerts:
        ts_str = alert.get('timestamp', '')
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', ''))
            key = ts.strftime('%Y-%m-%d')
            if key in day_counts:
                day_counts[key] += 1
        except (ValueError, TypeError):
            continue

    return [{'date': d, 'count': c} for d, c in day_counts.items()]


def build_dashboard_data(count: int = 100) -> dict:
    """Build a complete dashboard dataset from demo data."""
    incidents = generate_demo_incidents(count)
    alerts = generate_demo_alerts(incidents)
    secure_score = generate_demo_secure_score()
    daily_alerts = generate_demo_daily_alerts(alerts)

    high = sum(1 for i in incidents if i.get('severity') == 'High')
    medium = sum(1 for i in incidents if i.get('severity') == 'Medium')
    low = sum(1 for i in incidents if i.get('severity') == 'Low')
    informational = sum(1 for i in incidents if i.get('severity') == 'Informational')
    resolved = sum(1 for i in incidents if i.get('status') in ('Closed', 'Resolved'))
    active = sum(1 for i in incidents if i.get('status') in ('Active', 'New', 'InProgress'))

    return {
        'timestamp': datetime.now().isoformat(),
        'secureScore': {
            'current': secure_score['percentage'],
            'max': 100,
            'trend': 0,
            'isDemo': True,
            'rawScore': secure_score['currentScore'],
            'maxPossible': secure_score['maxScore'],
            'controlScores': secure_score['controlScores'],
            'categoryScores': secure_score['categoryScores'],
            'recommendations': secure_score['recommendations'],
        },
        'incidents': incidents,
        'alerts': alerts,
        'metrics': {
            'high': high,
            'medium': medium,
            'low': low,
            'informational': informational,
            'total': len(incidents),
            'resolved': resolved,
            'active': active,
        },
        'incidentSource': 'demo',
        'secureScoreTrend': [],
        'dailyAlerts': daily_alerts,
        'threatIntelligence': {},
        'mdtiArticles': [],
    }


def insert_into_db(incidents: list, alerts: list) -> None:
    """Insert demo data into the SQLite database."""
    try:
        from database import insert_incident, insert_alert
    except ImportError:
        print("❌ Could not import database module. Run from project root.")
        sys.exit(1)

    for inc in incidents:
        insert_incident(inc)
    print(f"  ✅ Inserted {len(incidents)} demo incidents into DB")

    for alert in alerts:
        insert_alert(alert)
    print(f"  ✅ Inserted {len(alerts)} demo alerts into DB")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Generate demo data for SOC Dashboard')
    parser.add_argument('--count', type=int, default=100, help='Number of incidents to generate (default: 100)')
    parser.add_argument('--db', action='store_true', help='Also insert into SQLite database')
    parser.add_argument('--output', default='dashboard_data.json', help='Output JSON file (default: dashboard_data.json)')
    args = parser.parse_args()

    print(f"🔧 Generating {args.count} demo incidents...")
    data = build_dashboard_data(args.count)

    with open(args.output, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"✅ Demo data saved to {args.output}")
    print(f"   📊 {len(data['incidents'])} incidents, {len(data['alerts'])} alerts")

    if args.db:
        print("📦 Inserting into database...")
        insert_into_db(data['incidents'], data['alerts'])

    print("✅ Done")


if __name__ == '__main__':
    main()
