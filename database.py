"""
SQLite Database Schema and Operations for SOC Dashboard
Supports append operations, historical data, and timeline filtering
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import os

DB_FILE = 'soc_dashboard.db'

def get_connection():
    """Get database connection with row factory for dict results"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize database schema"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Incidents table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            created_time TIMESTAMP NOT NULL,
            last_update_time TIMESTAMP,
            assigned_to TEXT,
            owner TEXT,
            classification TEXT,
            determination TEXT,
            alert_count INTEGER DEFAULT 0,
            entity_count INTEGER DEFAULT 0,
            web_url TEXT,
            data JSON NOT NULL,
            imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            category TEXT NOT NULL,
            product TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            detection_source TEXT,
            data JSON NOT NULL,
            imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    ''')
    
    # Entities table (for faster entity queries)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_name TEXT NOT NULL,
            verdict TEXT,
            data JSON NOT NULL,
            imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    ''')
    
    # Threat Intelligence snapshots
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_intel_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source TEXT NOT NULL,
            data JSON NOT NULL
        )
    ''')
    
    # Metrics snapshots (for trend analysis)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            secure_score REAL,
            total_incidents INTEGER,
            high_severity INTEGER,
            medium_severity INTEGER,
            low_severity INTEGER,
            informational INTEGER,
            active_incidents INTEGER,
            resolved_incidents INTEGER,
            data JSON NOT NULL
        )
    ''')
    
    # Create indices for common queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_time)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_entities_incident ON entities(incident_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type)')
    
    conn.commit()
    conn.close()
    print("✅ Database schema initialized")

def insert_incident(incident: Dict[str, Any]) -> bool:
    """Insert or update an incident"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT OR REPLACE INTO incidents 
            (id, title, severity, status, created_time, last_update_time, assigned_to, 
             owner, classification, determination, alert_count, entity_count, web_url, data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident.get('id'),
            incident.get('title'),
            incident.get('severity'),
            incident.get('status'),
            incident.get('createdTime') or incident.get('created'),
            incident.get('lastUpdateTime'),
            incident.get('assignedTo'),
            incident.get('owner'),
            incident.get('classification'),
            incident.get('determination'),
            incident.get('alertCount', 0),
            incident.get('entityCount', len(incident.get('entities', []))),
            incident.get('webUrl'),
            json.dumps(incident)
        ))
        
        # Insert entities
        for entity in incident.get('entities', []):
            cursor.execute('''
                INSERT INTO entities (incident_id, entity_type, entity_name, verdict, data)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                incident.get('id'),
                entity.get('type'),
                entity.get('name'),
                entity.get('verdict'),
                json.dumps(entity)
            ))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"❌ Error inserting incident {incident.get('id')}: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def insert_alert(alert: Dict[str, Any]) -> bool:
    """Insert or update an alert"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT OR REPLACE INTO alerts 
            (id, incident_id, title, severity, status, category, product, timestamp, detection_source, data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.get('id'),
            alert.get('incidentId'),
            alert.get('title'),
            alert.get('severity'),
            alert.get('status'),
            alert.get('category'),
            alert.get('product'),
            alert.get('timestamp'),
            alert.get('detectionSource'),
            json.dumps(alert)
        ))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"❌ Error inserting alert {alert.get('id')}: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def get_incidents(days: Optional[int] = None, 
                  start_date: Optional[str] = None,
                  end_date: Optional[str] = None,
                  severity: Optional[str] = None,
                  status: Optional[str] = None,
                  limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Query incidents with flexible filtering
    
    Args:
        days: Get incidents from last N days
        start_date: ISO format date string
        end_date: ISO format date string
        severity: Filter by severity (High, Medium, Low, Informational)
        status: Filter by status (Active, New, Resolved, etc.)
        limit: Maximum number of results
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT data FROM incidents WHERE 1=1"
    params = []
    
    # Date filtering
    if days:
        cutoff = datetime.now() - timedelta(days=days)
        query += " AND created_time >= ?"
        params.append(cutoff.isoformat())
    elif start_date and end_date:
        query += " AND created_time BETWEEN ? AND ?"
        params.append(start_date)
        params.append(end_date)
    elif start_date:
        query += " AND created_time >= ?"
        params.append(start_date)
    elif end_date:
        query += " AND created_time <= ?"
        params.append(end_date)
    
    # Severity filtering
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    
    # Status filtering
    if status:
        query += " AND status = ?"
        params.append(status)
    
    # Ordering and limit
    query += " ORDER BY created_time DESC"
    if limit:
        query += f" LIMIT {limit}"
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    return [json.loads(row['data']) for row in rows]

def get_alerts(incident_id: Optional[str] = None,
               days: Optional[int] = None,
               start_date: Optional[str] = None,
               end_date: Optional[str] = None) -> List[Dict[str, Any]]:
    """Query alerts with filtering"""
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT data FROM alerts WHERE 1=1"
    params = []
    
    if incident_id:
        query += " AND incident_id = ?"
        params.append(incident_id)
    
    if days:
        cutoff = datetime.now() - timedelta(days=days)
        query += " AND timestamp >= ?"
        params.append(cutoff.isoformat())
    elif start_date and end_date:
        query += " AND timestamp BETWEEN ? AND ?"
        params.append(start_date)
        params.append(end_date)
    
    query += " ORDER BY timestamp DESC"
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    return [json.loads(row['data']) for row in rows]

def get_metrics_summary(days: int = 30) -> Dict[str, Any]:
    """Get aggregated metrics for the dashboard"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cutoff = datetime.now() - timedelta(days=days)
    
    cursor.execute('''
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) as low,
            SUM(CASE WHEN severity = 'Informational' THEN 1 ELSE 0 END) as informational,
            SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) as resolved,
            SUM(CASE WHEN status IN ('Active', 'New') THEN 1 ELSE 0 END) as active
        FROM incidents
        WHERE created_time >= ?
    ''', (cutoff.isoformat(),))
    
    row = cursor.fetchone()
    conn.close()
    
    return {
        'total': row['total'],
        'high': row['high'],
        'medium': row['medium'],
        'low': row['low'],
        'informational': row['informational'],
        'resolved': row['resolved'],
        'active': row['active']
    }

def save_threat_intel_snapshot(source: str, data: Dict[str, Any]):
    """Save a threat intelligence snapshot"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO threat_intel_snapshots (source, data)
        VALUES (?, ?)
    ''', (source, json.dumps(data)))
    
    conn.commit()
    conn.close()

def get_latest_threat_intel() -> Dict[str, Any]:
    """Get the most recent threat intelligence data"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT source, data, timestamp
        FROM threat_intel_snapshots
        ORDER BY timestamp DESC
        LIMIT 1
    ''')
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            'source': row['source'],
            'data': json.loads(row['data']),
            'timestamp': row['timestamp']
        }
    return {}

def get_database_stats() -> Dict[str, Any]:
    """Get statistics about the database"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) as count FROM incidents')
    incident_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM alerts')
    alert_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM entities')
    entity_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT MIN(created_time) as oldest, MAX(created_time) as newest FROM incidents')
    date_range = cursor.fetchone()
    
    conn.close()
    
    return {
        'incidents': incident_count,
        'alerts': alert_count,
        'entities': entity_count,
        'oldest_incident': date_range['oldest'],
        'newest_incident': date_range['newest']
    }

if __name__ == '__main__':
    print("Initializing SOC Dashboard Database...")
    init_database()
    print("\n📊 Database created successfully!")
    print(f"📁 Database file: {os.path.abspath(DB_FILE)}")
