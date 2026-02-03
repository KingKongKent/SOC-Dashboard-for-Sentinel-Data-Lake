"""
Append new data to SQLite database instead of regenerating everything
Run this script periodically (e.g., every 15 minutes) to append new incidents/alerts
"""

from database import (
    get_connection,
    insert_incident,
    insert_alert,
    save_threat_intel_snapshot,
    get_database_stats,
    get_incidents
)
from fetch_live_data import (
    fetch_defender_incidents,
    fetch_defender_alerts_list,
    fetch_threat_intelligence,
    fetch_secure_score,
    calculate_daily_alert_volume
)
import json
from datetime import datetime

def fetch_and_append_new_data():
    """
    Fetch new incidents/alerts and append to database
    Only adds new data, doesn't regenerate existing data
    """
    print("\n=== Appending New Data to SOC Dashboard Database ===\n")
    
    # Get existing incident IDs from database
    print("1️⃣  Checking existing incidents...")
    existing_incidents = get_incidents(days=90)  # Last 90 days
    existing_ids = set(inc.get('id') for inc in existing_incidents)
    print(f"   📊 Found {len(existing_ids)} existing incidents in database")
    
    # Fetch latest incidents from Defender
    print("\n2️⃣  Fetching new incidents from Defender...")
    all_incidents = fetch_defender_incidents()
    
    # Filter to only new incidents
    new_incidents = [inc for inc in all_incidents if inc.get('id') not in existing_ids]
    print(f"   ✅ Found {len(new_incidents)} new incidents to add")
    
    # Insert new incidents
    if new_incidents:
        print("\n3️⃣  Inserting new incidents into database...")
        success_count = 0
        for incident in new_incidents:
            if insert_incident(incident):
                success_count += 1
        print(f"   ✅ Successfully inserted {success_count}/{len(new_incidents)} incidents")
    
    # Fetch and append alerts
    print("\n4️⃣  Fetching alerts for incidents...")
    all_alerts = fetch_defender_alerts_list(all_incidents)
    
    # Get existing alert IDs
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM alerts")
    existing_alert_ids = set(row[0] for row in cursor.fetchall())
    conn.close()
    
    new_alerts = [alert for alert in all_alerts if alert.get('id') not in existing_alert_ids]
    print(f"   📊 Found {len(new_alerts)} new alerts to add")
    
    if new_alerts:
        print("\n5️⃣  Inserting new alerts into database...")
        success_count = 0
        for alert in new_alerts:
            if insert_alert(alert):
                success_count += 1
        print(f"   ✅ Successfully inserted {success_count}/{len(new_alerts)} alerts")
    
    # Update threat intelligence (always get latest)
    print("\n6️⃣  Updating threat intelligence...")
    threat_intel = fetch_threat_intelligence(all_incidents, all_alerts)
    save_threat_intel_snapshot('auto_update', threat_intel)
    print(f"   ✅ Saved threat intelligence snapshot")
    
    # Show updated stats
    print("\n7️⃣  Database Statistics:")
    stats = get_database_stats()
    print(f"   • Total Incidents: {stats['incidents']}")
    print(f"   • Total Alerts: {stats['alerts']}")
    print(f"   • Total Entities: {stats['entities']}")
    print(f"   • Date Range: {stats['oldest_incident']} to {stats['newest_incident']}")
    
    print("\n✅ Data append completed successfully!\n")
    
    return {
        'new_incidents': len(new_incidents),
        'new_alerts': len(new_alerts),
        'total_incidents': stats['incidents'],
        'total_alerts': stats['alerts']
    }

if __name__ == '__main__':
    result = fetch_and_append_new_data()
    print(f"📊 Summary: Added {result['new_incidents']} incidents and {result['new_alerts']} alerts")
    print(f"💾 Total in DB: {result['total_incidents']} incidents, {result['total_alerts']} alerts")
