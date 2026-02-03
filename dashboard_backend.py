"""
SOC Dashboard Backend - Serves data from SQLite database with timeline filtering
"""
from flask import Flask, jsonify, send_file, send_from_directory, request
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import os

# Import database functions
try:
    from database import (
        get_incidents,
        get_alerts,
        get_metrics_summary,
        get_latest_threat_intel,
        get_database_stats
    )
    from fetch_live_data import fetch_secure_score, calculate_daily_alert_volume
    DB_AVAILABLE = True
except ImportError:
    print("⚠️  Database module not available, falling back to JSON mode")
    DB_AVAILABLE = False

app = Flask(__name__)
CORS(app)

@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    return send_from_directory(os.path.join(app.root_path, 'static'),
                             'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/api/dashboard-data', methods=['GET'])
def get_dashboard_data():
    """
    Serve dashboard data from SQLite database with filtering
    
    Query Parameters:
        days: Get data from last N days (e.g., ?days=7)
        start_date: ISO format start date (e.g., ?start_date=2026-01-01)
        end_date: ISO format end date (e.g., ?end_date=2026-02-03)
        severity: Filter by severity (e.g., ?severity=High)
        status: Filter by status (e.g., ?status=Active)
    """
    
    # Use database if available, otherwise fall back to JSON
    if DB_AVAILABLE:
        return get_dashboard_data_from_db()
    else:
        return get_dashboard_data_from_json()

def get_dashboard_data_from_db():
    """Get dashboard data from SQLite database with filtering"""
    try:
        # Get query parameters
        days = request.args.get('days', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        severity = request.args.get('severity')
        status = request.args.get('status')
        
        # Default to last 30 days if no filter specified
        if not any([days, start_date, end_date]):
            days = 30
        
        print(f"\n📊 Querying database with filters:")
        if days:
            print(f"   • Last {days} days")
        if start_date:
            print(f"   • Start date: {start_date}")
        if end_date:
            print(f"   • End date: {end_date}")
        if severity:
            print(f"   • Severity: {severity}")
        if status:
            print(f"   • Status: {status}")
        
        # Query incidents
        incidents = get_incidents(
            days=days,
            start_date=start_date,
            end_date=end_date,
            severity=severity,
            status=status
        )
        
        # Get alerts for the filtered incidents
        incident_ids = [inc.get('id') for inc in incidents]
        alerts = get_alerts(days=days, start_date=start_date, end_date=end_date)
        
        # Filter alerts to only those related to our incidents
        alerts = [a for a in alerts if a.get('incidentId') in incident_ids]
        
        # Get metrics for the filtered period
        metrics_days = days if days else 30
        metrics = get_metrics_summary(days=metrics_days)
        
        # Get latest threat intelligence
        threat_intel_data = get_latest_threat_intel()
        threat_intel = threat_intel_data.get('data', {}) if threat_intel_data else {}
        
        # Get secure score (always latest)
        secure_score_data = fetch_secure_score()
        
        # Calculate daily alert volume
        daily_alerts = calculate_daily_alert_volume(alerts)
        
        # Build response
        data = {
            'timestamp': datetime.now().isoformat(),
            'dataSource': 'sqlite_database',
            'filters': {
                'days': days,
                'start_date': start_date,
                'end_date': end_date,
                'severity': severity,
                'status': status
            },
            'secureScore': {
                'current': secure_score_data.get('percentage', 78.4),
                'max': 100,
                'trend': 5.2,
                'isDemo': secure_score_data.get('source') != 'microsoft_graph_api',
                'rawScore': secure_score_data.get('currentScore'),
                'maxPossible': secure_score_data.get('maxScore'),
                'controlScores': secure_score_data.get('controlScores', []),
                'categoryScores': secure_score_data.get('categoryScores', []),
                'recommendations': secure_score_data.get('recommendations', [])
            },
            'incidents': incidents,
            'alerts': alerts,
            'metrics': metrics,
            'secureScoreTrend': [],
            'dailyAlerts': daily_alerts,
            'threatIntelligence': threat_intel
        }
        
        print(f"✅ Serving {len(incidents)} incidents and {len(alerts)} alerts from database")
        return jsonify(data)
        
    except Exception as e:
        print(f"❌ Error querying database: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Database query failed',
            'message': str(e)
        }), 500

def get_dashboard_data_from_json():
    """Fallback: Get dashboard data from JSON file"""
    try:
        data_file = 'dashboard_data.json'
        
        # Check if data file exists
        if not os.path.exists(data_file):
            return jsonify({
                'error': 'Dashboard data not found',
                'message': 'Please run "python migrate_json_to_db.py" to set up the database'
            }), 404
        
        # Read the pre-fetched data
        with open(data_file, 'r') as f:
            data = json.load(f)
        
        data['dataSource'] = 'json_file'
        print(f"✅ Serving dashboard data from {data_file} (fallback mode)")
        print(f"   📊 Last updated: {data.get('timestamp')}")
        print(f"   📊 {len(data.get('incidents', []))} incidents, {len(data.get('alerts', []))} alerts")
        print(f"   📊 Secure Score: {data.get('secureScore', {}).get('current')}%")
        
        return jsonify(data)
        
    except json.JSONDecodeError as e:
        return jsonify({
            'error': 'Invalid data file',
            'message': f'Error reading dashboard_data.json: {str(e)}'
        }), 500
    except Exception as e:
        print(f"❌ Error serving dashboard data: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Server error',
            'message': str(e)
        }), 500

@app.route('/api/database-stats', methods=['GET'])
def get_db_stats():
    """Get database statistics"""
    if not DB_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        stats = get_database_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/')
def serve_dashboard():
    """Serve the dashboard HTML"""
    return send_file('soc-dashboard-live.html')

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Starting SOC Dashboard Backend Server")
    print("="*60)
    
    if DB_AVAILABLE:
        print("✅ Database mode: SQLite with timeline filtering")
        try:
            stats = get_database_stats()
            print(f"📊 Database contains:")
            print(f"   • {stats['incidents']} incidents")
            print(f"   • {stats['alerts']} alerts")
            print(f"   • {stats['entities']} entities")
            print(f"   • Date range: {stats['oldest_incident']} to {stats['newest_incident']}")
        except:
            print("⚠️  Database exists but may be empty. Run: python migrate_json_to_db.py")
    else:
        print("⚠️  JSON fallback mode (database not available)")
    
    print("\n💡 API Endpoints:")
    print("   • GET /api/dashboard-data (supports filtering)")
    print("   • GET /api/dashboard-data?days=7 (last 7 days)")
    print("   • GET /api/dashboard-data?days=30 (last 30 days)")
    print("   • GET /api/dashboard-data?severity=High")
    print("   • GET /api/database-stats")
    print("\n🌐 Dashboard: http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
