"""
Migration Script: Import existing JSON data into SQLite database
Run this once to migrate from dashboard_data.json to soc_dashboard.db
"""

import json
from database import (
    init_database, 
    insert_incident, 
    insert_alert, 
    save_threat_intel_snapshot,
    get_database_stats
)

def migrate_from_json(json_file='dashboard_data.json'):
    """Migrate data from JSON file to SQLite database"""
    
    print("=" * 60)
    print("SOC Dashboard: JSON to SQLite Migration")
    print("=" * 60)
    
    # Initialize database
    print("\n1️⃣  Initializing database...")
    init_database()
    
    # Load JSON data
    print(f"\n2️⃣  Loading data from {json_file}...")
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        print(f"   ✅ Loaded JSON data successfully")
    except FileNotFoundError:
        print(f"   ❌ Error: {json_file} not found!")
        return False
    except json.JSONDecodeError as e:
        print(f"   ❌ Error: Invalid JSON format: {e}")
        return False
    
    # Migrate incidents
    print(f"\n3️⃣  Migrating incidents...")
    incidents = data.get('incidents', [])
    success_count = 0
    for incident in incidents:
        if insert_incident(incident):
            success_count += 1
    print(f"   ✅ Migrated {success_count}/{len(incidents)} incidents")
    
    # Migrate alerts
    print(f"\n4️⃣  Migrating alerts...")
    alerts = data.get('alerts', [])
    success_count = 0
    for alert in alerts:
        if insert_alert(alert):
            success_count += 1
    print(f"   ✅ Migrated {success_count}/{len(alerts)} alerts")
    
    # Save threat intelligence
    print(f"\n5️⃣  Migrating threat intelligence...")
    threat_intel = data.get('threatIntelligence', {})
    if threat_intel:
        save_threat_intel_snapshot('migration', threat_intel)
        print(f"   ✅ Saved threat intelligence snapshot")
    
    # Show database stats
    print(f"\n6️⃣  Verifying migration...")
    stats = get_database_stats()
    print(f"   📊 Database Statistics:")
    print(f"      • Incidents: {stats['incidents']}")
    print(f"      • Alerts: {stats['alerts']}")
    print(f"      • Entities: {stats['entities']}")
    print(f"      • Date Range: {stats['oldest_incident']} to {stats['newest_incident']}")
    
    print("\n" + "=" * 60)
    print("✅ Migration completed successfully!")
    print("=" * 60)
    print("\n💡 Next steps:")
    print("   1. Test the dashboard with: python dashboard_backend.py")
    print("   2. If everything works, the old JSON file is backed up")
    print("   3. To rollback: python rollback_to_json.py")
    print()
    
    return True

if __name__ == '__main__':
    migrate_from_json()
